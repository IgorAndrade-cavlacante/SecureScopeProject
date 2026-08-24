# Kit enxuto para demonstrar os scanners

Os arquivos desta pasta foram preparados para gerar poucos resultados e manter
a gravação do vídeo compreensível.

## SAST — um achado esperado

Envie `demo_sast_enxuto.py` na aba SAST. O Bandit deve apontar somente o uso de
MD5 (`B324`). O arquivo é analisado como texto e nunca é executado.

## SCA — poucos achados esperados

Envie `requirements_sca_demo.txt` na aba SCA. A versão escolhida do Flask tinha
dois registros na OSV em 24/08/2026. Como a OSV é atualizada continuamente, a
quantidade pode mudar no futuro.

## DAST — cerca de dois achados controlados

Esta demonstração deve ser feita localmente, em duas janelas de terminal:

1. Defina `DAST_PERMITIR_REDE_INTERNA=true` apenas no ambiente local do
   SecureScope. Nunca habilite essa opção no Render.
2. Inicie o alvo controlado:

   `python scanner-test-files\demo_dast_alvo.py`

3. Inicie o SecureScope localmente e analise `http://127.0.0.1:5055/`.

Sem um daemon OWASP ZAP, o SecureScope fará uma análise passiva HTTP real. Os
dois achados esperados são o cookie `session_demo` sem HttpOnly e a versão do
servidor de desenvolvimento. Nenhum payload de ataque é enviado.

Use somente sistemas próprios, ambientes de homologação autorizados ou alvos
deliberadamente vulneráveis. Não execute Active Scan contra sites de terceiros.
