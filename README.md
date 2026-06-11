# SecRepoGuard

Ferramenta CLI educacional para auditoria basica de seguranca em repositorios
publicos do GitHub ou projetos locais. O SecRepoGuard procura potenciais
segredos expostos e compara dependencias declaradas com uma pequena base local
de versoes antigas ou de risco.

> Os resultados sao heurísticos e exigem validacao humana. A ferramenta nao
> substitui secret scanners, SAST, SCA ou uma auditoria profissional.

## Problema abordado

Credenciais inseridas no codigo-fonte e dependencias antigas ampliam a
superficie de ataque de um projeto. Em atividades academicas, reproduzir uma
verificacao simples desses riscos ajuda a compreender controles preventivos
sem depender de servicos externos.

## Motivacao em Ciberseguranca

O projeto demonstra principios de desenvolvimento seguro: minimo privilegio,
nao execucao de codigo nao confiavel, protecao de dados sensiveis em relatorios,
analise estatica, atualizacao de componentes e resultados reproduziveis.

## Funcionalidades

- clonagem rasa por padrao e clonagem completa quando o historico e solicitado;
- analise de projeto local sem clonagem;
- deteccao por expressoes regulares de chaves, senhas, tokens, URLs de banco,
  chaves privadas e possiveis JWTs;
- mascaramento do valor sensivel em todos os relatorios;
- leitura de `requirements.txt`, `dependencies` e `devDependencies`;
- base local deterministica para classificacao de versoes;
- saida no terminal e exportacao em TXT e JSON;
- modos exclusivos para segredos ou dependencias;
- busca opcional de segredos em linhas adicionadas aos commits Git;
- remocao automatica do clone temporario;
- testes automatizados com `pytest`.

## Escopo e limitacoes

O SecRepoGuard realiza uma triagem estatica e offline. Ele nao consulta CVEs,
nao resolve arvores transitivas, nao interpreta todos os formatos de versao e
inspeciona apenas linhas adicionadas nos diffs quando o modo de historico e
ativado. Expressoes regulares podem gerar falsos positivos e falsos negativos.
A base local e deliberadamente pequena e seus limiares devem ser revisados.

O scanner nao executa arquivos, nao instala pacotes do projeto, nao envia dados
e ignora links simbolicos, arquivos provavelmente binarios, arquivos maiores
que 1 MB e diretorios pesados.

## Dependencias

- Python 3.10 ou superior;
- Git, somente para usar `--repo`;
- `pytest`, somente para executar os testes.

A execucao da ferramenta usa apenas a biblioteca padrao do Python.

## Instalacao

```bash
git clone https://github.com/SEU_USUARIO/secrepoguard.git
cd secrepoguard
python -m venv .venv
```

Ative o ambiente virtual:

```bash
# Linux/macOS
source .venv/bin/activate

# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

Instale apenas a dependencia de teste:

```bash
python -m pip install -r requirements.txt
```

## Como executar com repositorio GitHub

```bash
python secrepoguard.py --repo https://github.com/usuario/projeto --all
```

Tambem e aceito o sufixo `.git`. O clone temporario e apagado ao final. Para
preserva-lo e exibir seu caminho:

```bash
python secrepoguard.py --repo https://github.com/usuario/projeto.git --all --keep
```

## Como procurar segredos nos commits

Use apenas em repositorios que voce possui ou tem autorizacao para auditar:

```bash
python secrepoguard.py \
  --repo https://github.com/usuario/projeto \
  --scan-history \
  --output reports/history_report.txt
```

Por padrao, os 100 commits mais recentes de todas as referencias sao
analisados. Para aumentar o limite:

```bash
python secrepoguard.py --repo https://github.com/usuario/projeto \
  --scan-history --history-limit 500
```

Use `--history-limit 0` para todos os commits, considerando que repositorios
grandes podem exigir bastante tempo, memoria, rede e espaco em disco. Para
analisar simultaneamente a arvore atual, dependencias e historico:

```bash
python secrepoguard.py --repo https://github.com/usuario/projeto \
  --all --scan-history
```

O relatorio informa o hash abreviado, arquivo e linha adicionada, sempre com o
possivel segredo mascarado. Remover uma credencial no commit atual nao a
invalida: se ela foi real, rotacione ou revogue imediatamente e depois avalie
a reescrita do historico.

Formatos reconhecidos incluem variaveis como `OPENAI_API_KEY`,
`GOOGLE_API_KEY` e `GITHUB_TOKEN`, alem de formatos conhecidos de tokens do
GitHub, Google, AWS, Stripe, Slack e OpenAI.

Se uma chave conhecida nao aparecer:

1. Execute com `--history-limit 0`, pois o padrao cobre apenas 100 commits.
2. Confira no resumo quantos commits foram analisados ou ignorados por tamanho.
3. Confirme que o commit pertence a uma branch ou referencia ainda acessivel.
4. Observe que commits soltos, apagados do servidor ou exclusivos de forks e
   pull requests nao baixados podem nao existir no clone.
5. Chaves de provedores ainda sem regra podem exigir um novo padrao.

## Como executar com pasta local

```bash
python secrepoguard.py --path examples/vulnerable_project --all
```

Sem uma opcao de scanner, o comportamento padrao tambem executa ambas as
analises. Para executar apenas uma:

```bash
python secrepoguard.py --path examples/vulnerable_project --scan-secrets
python secrepoguard.py --path examples/vulnerable_project --scan-dependencies
```

## Como gerar relatorio TXT

```bash
python secrepoguard.py --path examples/vulnerable_project --all \
  --output reports/generated_report.txt
```

## Como gerar relatorio JSON

```bash
python secrepoguard.py --path examples/vulnerable_project --all \
  --json reports/generated_report.json
```

As duas opcoes podem ser usadas na mesma execucao.

## Teste minimo reproduzivel

Na raiz do projeto:

```bash
python secrepoguard.py --path examples/vulnerable_project --all \
  --output reports/generated_report.txt \
  --json reports/generated_report.json
```

Resultado esperado: deteccao de credenciais ficticias, uma chave privada
ficticia e dependencias antigas como `django`, `requests`, `lodash` e
`minimist`. Nenhum valor completo deve aparecer nos trechos do relatorio.

## Estrutura do repositorio

```text
secrepoguard/
|-- README.md
|-- LICENSE
|-- requirements.txt
|-- secrepoguard.py
|-- relato_ia.txt
|-- secrepoguard_core/
|   |-- cli.py
|   |-- github.py
|   |-- scanner.py
|   |-- secrets.py
|   |-- dependencies.py
|   |-- report.py
|   `-- utils.py
|-- examples/vulnerable_project/
|-- reports/example_report.txt
`-- tests/
```

## Exemplo de saida

```text
SecRepoGuard - Relatorio de Auditoria
Origem analisada: examples/vulnerable_project
Segredos potenciais: 5
Dependencias analisadas: 8

[HIGH] Senha hardcoded
Arquivo: app.py
Linha: 5
Trecho: DB_PASSWORD = "fake********"
Recomendacao: mova a senha para uma variavel de ambiente.
```

Os totais podem mudar quando os exemplos ou as regras forem atualizados.

## Testes automatizados

```bash
python -m pytest -q
```

A suite verifica deteccao e mascaramento de segredos, chave privada, leitura de
arquivos de dependencias, comparacao de versoes, geracao dos dois formatos de
relatorio e exclusao de diretorios ignorados.

## Preocupacoes com seguranca

- nenhum codigo do alvo e importado ou executado;
- nenhuma dependencia do alvo e instalada;
- nenhum dado e enviado a servicos externos;
- o comando Git usa argumentos separados e nao passa pela shell;
- o clone usa historico raso e timeout;
- a clonagem completa so ocorre quando `--scan-history` e solicitado;
- links simbolicos nao sao seguidos;
- arquivos grandes, binarios e diretorios conhecidos sao descartados;
- achados de segredos sao mascarados antes da exibicao;
- repositorios temporarios sao removidos por padrao.

Nao use o projeto vulneravel de exemplo em producao. Todos os valores contidos
nele sao ficticios.

## Criterios de avaliacao de artefatos

### Disponibilidade

O codigo, os exemplos, os testes, a licença e a documentacao ficam no mesmo
repositorio e podem ser publicados diretamente no GitHub.

### Funcionalidade

A CLI cobre entrada remota ou local, modos de analise independentes, protecoes
de leitura, relatorio no terminal e exportacao em TXT e JSON. Os testes
automatizados validam os fluxos centrais.

### Sustentabilidade

Os modulos possuem responsabilidades pequenas. A base de riscos esta
centralizada em `dependencies.py`, permitindo adicionar pacotes e limiares sem
alterar a CLI ou os relatórios.

### Reprodutibilidade

A analise nao depende de APIs, banco de dados ou rede quando `--path` e usado.
O exemplo vulneravel e o comando de teste minimo permitem reproduzir os achados
em qualquer ambiente com Python 3.10+.

## Trabalho futuro

- consumir bases oficiais de vulnerabilidades de forma opcional;
- analisar arquivos de lock e dependencias transitivas;
- ampliar a analise do historico com allowlists e deteccao por entropia;
- adicionar allowlist configuravel e verificacao de entropia;
- suportar formatos como `pyproject.toml`, `Pipfile` e outros gerenciadores;
- gerar SARIF para integracao com plataformas de desenvolvimento;
- ampliar testes de compatibilidade entre sistemas operacionais.

## Licenca

Distribuido sob a licença MIT. Consulte [LICENSE](LICENSE).

## Referencias

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Software Component Verification Standard](https://owasp.org/www-project-software-component-verification-standard/)
- [GitHub: Removendo dados sensiveis de um repositorio](https://docs.github.com/pt/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [Python argparse](https://docs.python.org/3/library/argparse.html)
- [Python subprocess](https://docs.python.org/3/library/subprocess.html)
