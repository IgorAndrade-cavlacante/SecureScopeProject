"""Execute `python worker.py` no mesmo ambiente/banco da aplicação."""
import os
import argparse

# O processo dedicado não deve iniciar também uma thread embutida.
os.environ['SCAN_WORKER_EMBUTIDO'] = '0'
import app  # configura banco, migrações e serializador
import scan_jobs

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--scan', type=int)
    parser.add_argument('--token')
    args = parser.parse_args()
    if args.scan:
        with scan_jobs.conexao() as conn:
            job = conn.execute("SELECT * FROM scans WHERE id = ? AND token_execucao = ? AND status = 'em_progresso'",
                               (args.scan, args.token)).fetchone()
        if job:
            scan_jobs.executar(job)
    else:
        scan_jobs.loop_worker()
