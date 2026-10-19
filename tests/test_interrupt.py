import os,pty,select,time,signal,tempfile
from pathlib import Path
command=str(Path(__file__).resolve().parents[1] / 'reconator')

def session(args, initial_prompt, setup=None, terminate=False, menu_scan=False):
    pid,fd=pty.fork()
    if pid==0:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        os.environ['TERM']='xterm'
        if setup: os.environ.update(setup)
        os.execv(command,[command,*args])
    output=b''
    def expect(text,timeout=8):
        nonlocal output
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            if text.encode() in output: return
            ready,_,_=select.select([fd],[],[],0.2)
            if ready:
                try: output+=os.read(fd,65536)
                except OSError: break
        raise AssertionError((text,output.decode(errors='replace')))
    try:
        expect(initial_prompt)
        if not args:
            expect('Select an option:')
            if menu_scan:
                os.write(fd,b'02\nexample.com\n');expect('nmap started')
        time.sleep(0.1)
        if terminate:
            os.kill(pid,signal.SIGTERM)
        else:
            os.write(fd,b'\x03');expect('Press Ctrl+C again to close Reconator.')
            assert os.waitpid(pid,os.WNOHANG)==(0,0),'first Ctrl+C exited'
            os.write(fd,b'\x03');expect('Closing Reconator.')
        end=time.monotonic()+15
        while time.monotonic()<end:
            got,status=os.waitpid(pid,os.WNOHANG)
            if got:
                assert os.waitstatus_to_exitcode(status)==(143 if terminate else 130),(status,output)
                return
            time.sleep(.05)
        raise AssertionError('shutdown did not finish within 15 seconds')
    finally:
        try: os.kill(pid,signal.SIGKILL)
        except ProcessLookupError: pass
        os.close(fd)

session([], 'Select an option:')
# Exercise the same signal behavior while an external scanner is running.
with tempfile.TemporaryDirectory(dir=os.environ.get('RECONATOR_TEST_TMPDIR')) as tmp:
    t=Path(tmp).resolve();mock=t/'nmap';mock.write_text('#!/bin/bash\necho MOCK_SCANNER_STARTED >&2\nsleep 30\n');mock.chmod(0o755)
    session(['scan','-d','example.com','--nmap-only','--output',str(t/'results')], 'nmap started',{'RECONATOR_TOOL_BIN':str(t),'PATH':str(t)+':'+os.environ['PATH']})
    assert not list((t/'results').rglob('.lock')),'interrupted scan left its lock'
    session(['scan','-d','example.com','--nmap-only','--output',str(t/'term')], 'nmap started',{'RECONATOR_TOOL_BIN':str(t),'PATH':str(t)+':'+os.environ['PATH']},terminate=True)
    (t/'ping').write_text('#!/bin/bash\nexit 0\n');(t/'ping').chmod(0o755)
    (t/'curl').write_text('#!/bin/bash\nexit 7\n');(t/'curl').chmod(0o755)
    session([], 'Select an option:', {'RECONATOR_TOOL_BIN':str(t),'PATH':str(t)+':'+os.environ['PATH'],'RECONATOR_RESULTS':str(t/'menu-term')},terminate=True,menu_scan=True)
    assert not list((t/'menu-term').rglob('.lock'))
    assert not list((t/'term').rglob('.lock'))
    for file in (t/'term').rglob('scan-status.txt'): assert file.read_text().strip()=='interrupted'
    for file in (t/'term').rglob('reports/report.json'): assert __import__('json').loads(file.read_text())['status']=='interrupted'
print('PASS: real terminal Ctrl+C twice and SIGTERM, interruption manifests/reports and lock cleanup.')
