"""One bounded lifecycle for reviewed adapters; no provider text enters diagnostics."""
from datetime import datetime
from email.utils import parsedate_to_datetime
import re
import time
import uuid

from cops.evidence import EvidenceError, build_envelope, decode_json, validate_envelope, validate_receipt
from cops.evidence.canonical import canonical, digest, timestamp, utc_now
from .interfaces import Result, Response
from .policy import Limits

REASONS = {'page_limit', 'attempt_limit', 'record_limit', 'byte_limit', 'storage_limit',
           'time_limit', 'response_limit', 'invalid_json', 'schema_drift', 'unsafe_destination',
           'cursor_cycle', 'cursor_expired', 'truncated_without_cursor', 'retry_continuation',
           'authentication', 'transport', 'throttled', 'request_timeout', 'checkpoint_invalid', 'projection_failed'}


def preview(adapter):
    """Build only the initial, credential-free request. No cursor or private response."""
    request = adapter.request()
    adapter.validate_request(request)
    return {'adapter': adapter.name, 'adapter_version': adapter.version, 'tenant': adapter.tenant,
            'scope': list(adapter.scope), 'method': request.method, 'url': request.url,
            'body': decode_json(request.body) if request.body else None,
            'headers': dict(request.headers)}


def _receipt(state, now):
    item = {key: state[key] for key in ('acquisition_id', 'generation', 'adapter', 'adapter_version',
            'tenant', 'scope', 'request_fingerprint', 'started_at', 'limits', 'consumed')}
    finished_at = state['finished_at'] if state['status'] in ('complete', 'partial') else _finish_time(state, now)
    item.update(schema_version='cops.acquisition/v1', finished_at=finished_at,
                status=state['status'], reasons=list(state['reasons']), consistency='unknown')
    return validate_receipt(item)


def _finish_time(state, now):
    return now if timestamp(now) >= timestamp(state['started_at']) else state['started_at']


def _delay(value, retry, now):
    if value is None:
        return min(2 ** retry, 30)
    if not isinstance(value, str) or len(value) > 128:
        raise EvidenceError('throttled')
    if re.fullmatch(r'[0-9]{1,8}', value):
        return float(value)
    try:
        date = parsedate_to_datetime(value)
        if date.tzinfo is None: raise ValueError
        return max(0, (date - datetime.fromisoformat(now.replace('Z', '+00:00'))).total_seconds())
    except (ValueError, TypeError, OverflowError):
        raise EvidenceError('throttled') from None


def collect(adapter, checkpoint, credentials, transport=None, *, limits=None,
            clock=time.monotonic, sleep=time.sleep, now=utc_now, fault=lambda phase: None):
    """Resume the same authorized query. Trusted callbacks must return promptly.

    Injected transports must enforce the supplied timeout and response byte cap.
    Crashes after a reservation retain its full cost, even when dispatch is unknown.
    """
    limits = limits or Limits()
    plan = preview(adapter)
    fingerprint = digest(plan)
    binding = dict(adapter=adapter.name, adapter_version=adapter.version, tenant=adapter.tenant,
                   scope=list(adapter.scope), request_fingerprint=fingerprint)
    state = checkpoint.load()
    if state is None:
        state = dict(binding, acquisition_id=str(uuid.uuid4()), generation=1, started_at=now(), finished_at=None,
                     limits=limits.export(), consumed=dict(pages=0, attempts=0, records=0, duplicates=0,
                                                          bytes=0, storage_bytes=0, active_seconds=0),
                     cursor=None, status='unknown', reasons=[], refreshed=False, reservation=False, retry=0)
        checkpoint.save(state)
    else:
        try:
            if any(state[key] != value for key, value in binding.items()):
                raise EvidenceError('resume_mismatch')
            previous = Limits(**state['limits'])
            if any(value > previous.export()[key] for key, value in limits.export().items()):
                raise EvidenceError('resume_limits')
            _receipt(state, now())
            counters = dict(pages='pages', attempts='attempts', records='records', bytes='total_bytes',
                            storage_bytes='storage_bytes', active_seconds='active_seconds')
            if any(state['consumed'][key] > limits.export()[bound] for key, bound in counters.items()):
                raise EvidenceError('resume_limits')
            records = checkpoint.export()
            if len(records) != state['consumed']['records'] or sum(len(canonical(record, max_bytes=previous.record_bytes, max_depth=previous.depth)) for record in records) != state['consumed']['storage_bytes']:
                raise EvidenceError('checkpoint_invalid')
            if type(state['retry']) is not int or not 0 <= state['retry'] <= previous.retries or type(state['refreshed']) is not bool or type(state['reservation']) is not bool:
                raise EvidenceError('checkpoint_invalid')
            if state['retry'] > limits.retries:
                raise EvidenceError('resume_limits')
            for record in records:
                validate_envelope(record, max_bytes=previous.record_bytes, max_depth=previous.depth)
                if record['acquisition_id'] != state['acquisition_id'] or record['source']['tenant'] != adapter.tenant or record['source']['scope'] != list(adapter.scope) or record['request_fingerprint'] != fingerprint:
                    raise EvidenceError('checkpoint_invalid')
                try:
                    canonical(record, max_bytes=limits.record_bytes, max_depth=limits.depth)
                except EvidenceError:
                    raise EvidenceError('resume_limits') from None
            if state['cursor'] is not None:
                adapter.validate_request(adapter.request(state['cursor']))
        except EvidenceError:
            raise
        except Exception:
            raise EvidenceError('checkpoint_invalid') from None
        state['generation'] += 1
        state['limits'] = limits.export()
        checkpoint.save(state)
    if state['status'] in ('complete', 'partial'):
        return Result(checkpoint.export(), _receipt(state, now()))
    if transport is None:
        from .transport import HttpsTransport
        transport = HttpsTransport(adapter.origin, adapter.path, adapter.method)
    spent = state['consumed']

    def finish(reason=None):
        state['status'] = 'partial' if reason else 'complete'
        state['reasons'] = [reason] if reason else []
        state['finished_at'] = _finish_time(state, now())
        checkpoint.save(state)
        return Result(checkpoint.export(), _receipt(state, now()))

    while True:
        for counter, maximum, reason in [('pages', limits.pages, 'page_limit'),
            ('attempts', limits.attempts, 'attempt_limit'), ('records', limits.records, 'record_limit'),
            ('bytes', limits.total_bytes, 'byte_limit'), ('storage_bytes', limits.storage_bytes, 'storage_limit'),
            ('active_seconds', limits.active_seconds, 'time_limit')]:
            if spent[counter] >= maximum:
                return finish(reason)
        try:
            request = adapter.request(state['cursor'])
            adapter.validate_request(request)
        except Exception:
            return finish('unsafe_destination')
        retry, refresh = state['retry'], False
        while True:
            if spent['attempts'] >= limits.attempts: return finish('attempt_limit')
            byte_cap = min(limits.response_bytes, limits.total_bytes - spent['bytes'])
            timeout = min(limits.request_seconds, limits.active_seconds - spent['active_seconds'])
            if byte_cap <= 0: return finish('byte_limit')
            if timeout <= 0: return finish('time_limit')
            # Validate destinations before every ephemeral credential lookup.
            try:
                adapter.validate_request(request)
                headers = credentials.headers(refresh=refresh)
                if not isinstance(headers, dict) or set(headers) != {'Authorization'} or not isinstance(headers['Authorization'], str) or not headers['Authorization'].startswith('Bearer ') or any(c in headers['Authorization'] for c in '\r\n'):
                    raise ValueError
            except Exception:
                return finish('authentication')
            refresh = False
            spent['attempts'] += 1
            spent['bytes'] += byte_cap
            spent['active_seconds'] += timeout
            state['reservation'] = True
            checkpoint.save(state)
            fault('after_reserve')
            began = clock()
            try:
                response = transport.send(request, headers, timeout=timeout, max_bytes=byte_cap)
                if not isinstance(response, Response) or type(response.body) is not bytes or type(response.status) is not int:
                    raise EvidenceError('transport')
                if len(response.body) > byte_cap:
                    raise EvidenceError('response_limit')
            except Exception as error:
                # Keep reserved bytes when actual transport consumption is unavailable.
                elapsed = max(0, clock() - began)
                spent['active_seconds'] -= timeout - min(timeout, elapsed)
                state['reservation'] = False
                checkpoint.save(state)
                code = error.code if isinstance(error, EvidenceError) and error.code in REASONS else 'transport'
                return finish(code)
            finally:
                # Credential values never enter the checkpoint, plan, receipt or result.
                headers = None
            elapsed = max(0, clock() - began)
            spent['bytes'] -= byte_cap - len(response.body)
            # Keep the active-time reservation until the page transaction commits.
            # An interruption during projection must not reset its processing cost.
            if response.status != 200 or elapsed >= timeout:
                spent['active_seconds'] -= timeout - min(timeout, elapsed)
                state['reservation'] = False
            checkpoint.save(state)
            if elapsed >= timeout: return finish('request_timeout')
            if response.status == 200: break
            if response.status in (400, 404, 410) and state['cursor'] is not None:
                return finish('cursor_expired')
            if response.status == 401:
                if state['refreshed']: return finish('authentication')
                # Persist before refresh so interruptions cannot grant more refreshes.
                state['refreshed'] = True
                checkpoint.save(state)
                refresh = True
            elif response.status not in (429, 500, 502, 503, 504):
                return finish('transport')
            if retry >= limits.retries:
                return finish('throttled' if response.status == 429 else 'authentication' if response.status == 401 else 'transport')
            try:
                delay = 0 if response.status == 401 else _delay(response.retry_after, retry, now())
            except EvidenceError as error:
                return finish(error.code)
            if delay >= limits.active_seconds - spent['active_seconds']:
                return finish('time_limit')
            # Reserve sleeps too: a crash must not reset backoff/time accounting.
            retry += 1
            state['retry'] = retry
            spent['active_seconds'] += delay
            checkpoint.save(state)
            began_sleep = clock()
            try:
                sleep(delay)
            except Exception:
                return finish('transport')
            oversleep = max(0, clock() - began_sleep - delay)
            spent['active_seconds'] = min(limits.active_seconds, spent['active_seconds'] + oversleep)
            checkpoint.save(state)
        parsed_at = clock()

        def check_page_time():
            actual = elapsed + max(0, clock() - parsed_at)
            if spent['active_seconds'] - timeout + actual >= limits.active_seconds:
                raise EvidenceError('time_limit')

        def settle_page_time():
            actual = elapsed + max(0, clock() - parsed_at)
            spent['active_seconds'] = min(limits.active_seconds,
                                         spent['active_seconds'] - timeout + actual)
            state['reservation'] = False

        try:
            check_page_time()
            data = decode_json(response.body, max_bytes=byte_cap, max_depth=limits.depth)
            check_page_time()
            page = adapter.parse(data, retried=retry > 0)
            check_page_time()
            stamp = now()
            pending, seen, duplicates, storage, reason = [], set(), 0, 0, page.reason
            cursor_hash = None
            try:
                projections = iter(page.records)
                while True:
                    check_page_time()
                    try:
                        projected = next(projections)
                    except StopIteration:
                        break
                    check_page_time()
                    record = build_envelope(acquisition_id=state['acquisition_id'], product=adapter.product,
                        api=adapter.api, tenant=adapter.tenant, scope=list(adapter.scope),
                        acquired_at=stamp, transformed_at=stamp, request_fingerprint=fingerprint,
                        page=spent['pages'] + 1, max_bytes=limits.record_bytes, max_depth=limits.depth, **projected)
                    check_page_time()
                    duplicate = checkpoint.contains(record['record_id']) or record['record_id'] in seen
                    check_page_time()
                    if duplicate:
                        duplicates += 1
                        continue
                    size = len(canonical(record, max_bytes=limits.record_bytes, max_depth=limits.depth))
                    check_page_time()
                    if spent['records'] + len(pending) >= limits.records:
                        reason = 'record_limit'; break
                    if spent['storage_bytes'] + storage + size > limits.storage_bytes:
                        reason = 'storage_limit'; break
                    pending.append(record); seen.add(record['record_id']); storage += size
                check_page_time()
                cursor_hash = digest(page.cursor) if page.cursor is not None else None
                check_page_time()
                if cursor_hash and checkpoint.seen_cursor(cursor_hash):
                    reason, cursor_hash = 'cursor_cycle', None
                check_page_time()
            except EvidenceError as error:
                if error.code != 'time_limit':
                    raise
                # Commit only the prefix accepted before this budget expired.
                reason, cursor_hash = 'time_limit', None
        except EvidenceError as error:
            settle_page_time()
            code = error.code if error.code in REASONS else 'projection_failed'
            return finish(code)
        except Exception:
            settle_page_time()
            return finish('schema_drift')
        settle_page_time()
        if spent['active_seconds'] >= limits.active_seconds:
            reason = 'time_limit'
        spent['pages'] += 1
        spent['records'] += len(pending)
        spent['duplicates'] += duplicates
        spent['storage_bytes'] += storage
        state['cursor'] = page.cursor
        state['retry'] = 0
        state['status'] = 'partial' if reason else 'complete' if page.cursor is None else 'unknown'
        state['reasons'] = [reason] if reason else []
        if state['status'] != 'unknown':
            state['finished_at'] = _finish_time(state, now())
        fault('before_commit')
        checkpoint.save(state, pending, cursor_hash)
        fault('after_commit')
        if state['status'] != 'unknown':
            return Result(checkpoint.export(), _receipt(state, now()))
