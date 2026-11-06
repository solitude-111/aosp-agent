"""Local scripted Responses transport to exercise real SDK sandbox commands.

No model, external service, CVE input or exploit is used. The deterministic
function call is a caller-supplied harmless filesystem canary command.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading


class ScriptedProvider:
    def __init__(self, command='', command_args=None, *, tool_calls=None, final_responses=None):
        self.command = command
        self.command_args = command_args or {}
        self.pending = False
        self.calls = 0
        self.tool_names = []
        self.tool_calls = tool_calls
        self.tool_index = 0
        self.tool_outputs = []
        self.final_responses = final_responses
        self.response_index = 0
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass

            def do_POST(self):
                data = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                if self.headers.get('Content-Encoding') == 'gzip':
                    import gzip
                    data = gzip.decompress(data)
                request = json.loads(data)
                owner.calls += 1
                owner.tool_names.append([t.get('name', t.get('type')) for t in request.get('tools', [])])
                owner.tool_outputs.extend(i for i in request.get('input', []) if i.get('type') == 'function_call_output')
                if not owner.pending:
                    owner.pending = True
                    name, arguments = ('exec_command', {'cmd': owner.command, 'max_output_tokens': 2000, **owner.command_args})
                    if owner.tool_calls is not None:
                        name, arguments = (owner.tool_calls[owner.tool_index] if owner.tool_index < len(owner.tool_calls)
                                           else ('unexpected_tool_call', {}))
                        owner.tool_index += 1
                    item = {'id': 'fc_' + str(owner.calls), 'type': 'function_call',
                            'call_id': 'call_' + str(owner.calls), 'name': name,
                            'arguments': json.dumps(arguments),
                            'status': 'completed'}
                else:
                    owner.pending = False
                    response_text = '{"probe":true}'
                    if owner.final_responses is not None and owner.response_index < len(owner.final_responses):
                        value = owner.final_responses[owner.response_index]
                        response_text = json.dumps(value) if isinstance(value, dict) else value
                        owner.response_index += 1
                    item = {'id': 'msg_' + str(owner.calls), 'type': 'message', 'role': 'assistant',
                            'status': 'completed', 'content': [{'type': 'output_text',
                                'text': response_text, 'annotations': []}]}
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.end_headers()
                response = {'id': 'resp_' + str(owner.calls), 'object': 'response',
                            'model': 'gpt-5.1-codex', 'status': 'completed', 'output': [item],
                            'usage': {'input_tokens': 1, 'output_tokens': 1, 'total_tokens': 2}}
                events = [
                    {'type': 'response.created', 'response': {**response, 'status': 'in_progress', 'output': []}},
                    {'type': 'response.output_item.added', 'output_index': 0, 'item': item},
                    {'type': 'response.output_item.done', 'output_index': 0, 'item': item},
                    {'type': 'response.completed', 'response': response}]
                for event in events:
                    self.wfile.write(('event: ' + event['type'] + '\ndata: ' + json.dumps(event) + '\n\n').encode())
                    self.wfile.flush()

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown(); self.thread.join(); self.server.server_close()

    def overrides(self):
        return ('model_providers.scope_probe.name="Scripted local sandbox test"',
                'model_providers.scope_probe.base_url="http://127.0.0.1:' + str(self.server.server_port) + '/v1"',
                'model_providers.scope_probe.wire_api="responses"',
                'model_providers.scope_probe.request_max_retries=0',
                'model_providers.scope_probe.stream_max_retries=0')


def command_output(result):
    return '\n'.join(item.get('aggregated_output', '') for item in result['items']
                     if item.get('type') == 'commandExecution')
