#!/usr/bin/env python3
"""Reprova interpolação de contexto CONTROLÁVEL PELO AUTOR dentro de `run:`.

Requisito `SEG-CD-02` da spec de segurança. Âncora: guia de endurecimento do
GitHub Actions — `${{ }}` é substituição de TEXTO feita antes de o shell rodar,
então um campo que o autor da PR escreve (título, corpo, nome de branch) vira
comando quando colado num `run:`. A defesa é passar por variável de ambiente,
onde o valor é dado e não código.

⚠️ POR QUE A REGRA NÃO É "proibir `${{ github.event.* }}` em `run:`"
A primeira redação do requisito dizia que a cerca era "uma linha". Não é: essa
regra ingênua REPROVA A `main` DE HOJE, e por falso positivo — o CI usa
`${{ github.event.pull_request.base.sha || github.event.before }}` e
`${{ github.event.pull_request.number }}`, que são SHA e número. Cerca que
reprova o que é seguro é cerca que alguém desliga.

O RECORTE, e ele é seguro por FORMA e não por lista
Dentro de `run:`, uma expressão que toque `github.event.*` só passa se a folha
estiver na lista de formas comprovadamente não-textuais (`sha`, `number`,
`before`, ...). Qualquer outra folha reprova, INCLUSIVE uma que ninguém previu:
o padrão é recusar, e a exceção é declarada. Isso é o contrário de uma lista de
campos perigosos, que envelhece a cada campo novo da API do GitHub.

Também reprovam, por serem texto de autor com nome próprio: `github.head_ref`,
`github.actor`, `github.triggering_actor` e `github.ref_name`.

COMO ELA LÊ OS WORKFLOWS, E POR QUE ISSO MUDOU
A primeira versão varria LINHA A LINHA, com rastreio de bloco por indentação.
Ela acumulou **seis bypass** em três rodadas de revisão, e todos exploravam a
mesma raiz: não entendia YAML. Índice no lugar de ponto; expressão partida num
escalar dobrado; escalar simples ou entre aspas continuando na linha seguinte;
heredoc com `run:` dentro desligando o rastreio no meio de um script.

Remendar cada forma é perder a corrida — quem escreve o bypass tem a gramática
inteira do YAML, e a cerca tinha as formas que alguém lembrou. Agora ela usa o
parser (`yaml.compose`), que devolve o valor de `run:` já dobrado e desescapado,
qualquer que seja a forma de escrita, e a linha vem da marca do nó.

LIMITAÇÕES DECLARADAS
1. `steps.*.outputs.*` é RECUSADO — a inversão para allowlist fechou isso —, mas
   por não conseguir PROVAR a origem, e não por rastreá-la. Um output
   comprovadamente seguro é recusado junto; o conserto é passar por `env:` e ler
   como variável do shell.
2. A linha do achado é exata no bloco literal e no escalar de uma linha só, que
   são as formas em que `run:` se escreve; segue aproximada no dobrado de vários
   parágrafos e no plano de várias linhas, onde o próprio YAML já descartou as
   quebras antes de a cerca ver o valor. ⚠️ Esta linha dizia "exata em bloco
   literal" enquanto o cálculo somava o deslocamento à marca do INDICADOR, e
   errava por um — a 10ª rodada mediu, `_linha_inicial` consertou e a lista
   `LINHAS` do autoteste passou a conferir a linha, um caso por estilo.
3. Depende do PyYAML. Ausente, a cerca **falha o boot do passo** em vez de
   passar verde: gate de segurança que some quando falta dependência é pior que
   gate nenhum.

Uso: ops/ci/checa-interpolacao-em-run.py [.github/workflows]
"""
import pathlib
import re
import sys
import textwrap

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - fail-closed, ver limitação 3
    print("ERRO: PyYAML ausente — a cerca do SEG-CD-02 não roda sem parser.")
    print("Instale com `pip install pyyaml` no passo que a executa.")
    raise SystemExit(2)

# Folhas de `github.event.*` que NÃO são texto de autor. Tudo fora daqui
# reprova — inclusive campo que ainda não existe.
FOLHAS_SEGURAS = {
    "sha",           # SHA de commit: hexadecimal, vem do git
    "before",        # idem, no push
    "after",         # idem
    "number",        # número da PR/issue: inteiro
    "id",            # identificador numérico da API
    "merged",        # booleano
    "draft",         # booleano
    "deleted",       # booleano
}

# O que se prova seguro dentro de `run:` — e nada além disto passa.
CONTEXTOS_SEGUROS = {
    "github.repository",       # dono/nome, fixo pelo repositório
    "github.repository_owner",
    "github.sha",
    "github.run_id",
    "github.run_number",
    "github.run_attempt",
    "github.job",
    "github.event_name",       # enum do gatilho, não texto de autor
    "github.workspace",
    "github.api_url",
    "github.server_url",
}

# Famílias inteiras seguras: valor de execução, não de autor.
PREFIXOS_SEGUROS = ("secrets.", "runner.", "job.", "strategy.")

# Estados que o RUNNER gera, não o autor: enum fechado (`success`, `failure`,
# `cancelled`, `skipped`). Recusá-los era falso positivo num gate obrigatório —
# achado da 8ª rodada da #245. ⚠️ `steps.*.outputs.*` continua FORA: output é o
# que um passo anterior escreveu, e pode ter copiado texto de autor.
# Recusas NOMEADAS no cabeçalho: contextos que são texto de autor com nome
# próprio. Com a allowlist eles já caem por não estarem entre os seguros — esta
# lista existe para a meta-checagem exigir um caso de cada, e assim ninguém
# poder liberá-los em CONTEXTOS_SEGUROS sem o autoteste reclamar.
RECUSAS_DECLARADAS = (
    "github.head_ref",         # nome da branch da PR
    "github.actor",            # login
    "github.triggering_actor",
    "github.ref_name",
    "github.ref",              # carrega o nome da branch/tag
    "github.workflow",         # nome do workflow, escolhido pela PR
)

# Coleções cujo conteúdo é TIPADO pelo GitHub, e onde agregar com `*` é seguro
# se a folha também for. Curinga fora daqui recusa — inclusive sobre caminho
# que "parece" conhecido, porque pode ter um objeto livre no meio.
COLECOES_TIPADAS = ("github.event.pull_request.labels.*",)

ESTADOS_DE_PASSO = ("outcome", "conclusion")
ESTADO_DE_DEPENDENCIA = "result"
ESTADO_TIPADO = re.compile(
    r"^(?:steps\.[A-Za-z0-9_-]+\.(?:" + "|".join(ESTADOS_DE_PASSO) + r")"
    r"|needs\.[A-Za-z0-9_-]+\." + ESTADO_DE_DEPENDENCIA + r")$"
)

# ⚠️ FICARAM DE FORA, e cada ausência é decisão: `env.*` e `matrix.*` porque
# podem ter recebido texto de autor uma linha antes e o Actions recola o valor
# no script; `steps.*.outputs.*` pelo mesmo motivo — era limitação declarada
# desta cerca e a inversão a fechou de graça; `inputs.*` porque é digitado por
# quem dispara; `github.ref` porque carrega o nome da branch, e nome de ref
# aceita metacaractere de shell.

# Caminhos que são texto de autor INTEIROS, qualquer que seja a folha: entrada
# de `workflow_dispatch` e corpo de `repository_dispatch` são digitados por
# quem dispara. Achado da revisão da #245: um input de nome `id` passaria pela
# lista de folhas seguras carregando texto arbitrário.
PREFIXOS_DE_AUTOR = (
    "github.event.inputs.",              # workflow_dispatch
    "github.event.client_payload.",      # repository_dispatch
    "github.event.deployment.payload.",  # objeto livre de quem cria o deployment
    "github.event.deployment_status.deployment.payload.",
    "inputs.",                           # workflow_call / dispatch
)

# Índice por aspas E índice numérico: `labels[0].id` é sintaxe válida de array,
# e sem normalizar o número a referência quebrava em duas — `...labels` e `id`
# —, recusando uma folha segura. Falso positivo num gate obrigatório, achado da
# 8ª rodada da #245.
INDICE = re.compile(r"\[\s*(?:['\"]([A-Za-z0-9_-]+)['\"]|(\d+))\s*\]")


def normalizar(expressao: str) -> str:
    """`github['event'].pull_request['title']` -> `github.event.pull_request.title`.

    A linguagem de expressão do GitHub aceita índice e ponto como equivalentes.
    Achado P1 da revisão da #245: sem esta normalização, a cerca inteira era
    contornável escrevendo `github['event']` — e o sacrifício documentado só
    exercitava a forma com ponto, então o furo passava por baixo dele.
    """
    return INDICE.sub(lambda m: "." + (m.group(1) or m.group(2)), expressao)


def _fim_da_expressao(texto: str, inicio: int) -> int:
    """Offset do `}}` que fecha a expressão aberta em `inicio`, ou -1.

    Aspas simples são as do Actions, e `''` escapa a própria aspa. `}}` DENTRO
    de string não fecha nada — foi o bypass da 3ª rodada da #245.
    """
    j = inicio
    em_aspas = False
    while j < len(texto):
        if texto[j] == "'":
            if em_aspas and texto.startswith("''", j):
                j += 2
                continue
            em_aspas = not em_aspas
        elif not em_aspas and texto.startswith("}}", j):
            return j
        j += 1
    return -1


def expressoes(texto: str):
    """Devolve (offset, conteúdo) de cada `${{ ... }}`, respeitando aspas."""
    i = 0
    while True:
        inicio = texto.find("${{", i)
        if inicio < 0:
            return
        fim = _fim_da_expressao(texto, inicio + 3)
        if fim < 0:
            return                       # expressão sem fechamento: nada a varrer
        yield inicio, texto[inicio + 3:fim]
        i = fim + 2


def folha(referencia: str) -> str:
    """Último segmento de `github.event.pull_request.base.sha` -> `sha`."""
    return referencia.split(".")[-1].strip("]'\" ")


def escalares_run(texto_do_arquivo: str):
    """Devolve (linha_inicial, valor) de cada `run:` — pelo PARSER, não por regex.

    🚨 **Por que parser, e por que a versão anterior não bastava.** A varredura
    por linha desta cerca acumulou **seis bypass** em duas rodadas de revisão, e
    todos exploravam a mesma raiz: ela não entendia YAML. Índice no lugar de
    ponto; expressão partida num escalar dobrado; escalar simples ou entre aspas
    continuando na linha seguinte; e conteúdo de heredoc começando com `run:`,
    que fazia o rastreio de bloco se perder no meio de um script.

    Remendar cada forma é perder a corrida: quem escreve o bypass tem a
    gramática inteira do YAML à disposição, e a cerca tinha as formas que eu
    lembrei. O parser resolve a classe: ele devolve o valor JÁ dobrado e
    desescapado, qualquer que seja a forma de escrita.

    A linha vem da marca do nó, então o erro continua apontando para o lugar
    certo.
    """
    try:
        raiz = yaml.compose(texto_do_arquivo)
    except yaml.YAMLError as erro:
        raise SystemExit(f"YAML inválido: {erro}")
    if raiz is None:
        return
    yield from _run_de(raiz)


def _valor(mapa, chave):
    """Valor de uma chave num MappingNode, ou None."""
    if not isinstance(mapa, yaml.MappingNode):
        return None
    for k, v in mapa.value:
        if isinstance(k, yaml.ScalarNode) and k.value == chave:
            return v
    return None


def _passos_de(mapa):
    """Sequência `steps` de um mapeamento, ou lista vazia."""
    passos = _valor(mapa, "steps")
    return passos.value if isinstance(passos, yaml.SequenceNode) else []


ESTILOS_DE_BLOCO = ("|", ">")


def _linha_inicial(script) -> int:
    """Linha (contada de 1) do PRIMEIRO caractere de conteúdo do escalar.

    🚨 **Num bloco, a marca do nó não é a linha do conteúdo.** Em `|` e `>` o
    `start_mark` aponta para o INDICADOR — a linha do `run: |` —, enquanto
    `script.value` já começa uma linha abaixo. Somar o deslocamento à marca
    reportava toda expressão de bloco **uma linha cedo**, e bloco literal é
    justamente a forma em que os scripts destes workflows são escritos: a
    anotação `::error` mandava o revisor para a linha do `run:`. Nos demais
    estilos (plano, `'` e `"`) a marca já é o conteúdo. Achado P2 da 10ª rodada
    da #245.
    """
    return script.start_mark.line + (2 if script.style in ESTILOS_DE_BLOCO else 1)


def _nos_run(raiz):
    """Cada nó escalar `run:` — de `jobs.*.steps[*]` e de action composta.

    ⚠️ Achado da terceira rodada da #245: a versão anterior varria QUALQUER
    chave `run` do documento. Uma action com input chamado `run`
    (`uses: ...` + `with: {run: ...}`) era lida como script de shell, e o
    workflow reprovava por um valor que o Actions nunca executa. Falso positivo
    numa cerca obrigatória é o que faz alguém pedir para desligá-la.
    """
    jobs = _valor(raiz, "jobs")
    if isinstance(jobs, yaml.MappingNode):
        for _, job in jobs.value:
            for passo in _passos_de(job):
                script = _valor(passo, "run")
                if isinstance(script, yaml.ScalarNode):
                    yield script

    # Action composta local: os comandos vivem em `runs.steps[*].run` de um
    # `action.yml`, e executam com o mesmo contexto de evento. Sem isto, uma
    # action composta adicionada pela PR ficaria INTEIRA fora do gate — achado
    # da 7ª rodada da #245.
    runs = _valor(raiz, "runs")
    for passo in _passos_de(runs) if runs is not None else []:
        script = _valor(passo, "run")
        if isinstance(script, yaml.ScalarNode):
            yield script


def _run_de(raiz):
    """Devolve (linha do conteúdo, script) de cada `run:` do documento."""
    for script in _nos_run(raiz):
        yield _linha_inicial(script), script.value


LITERAL = re.compile(r"'(?:[^']|'')*'")
ESPACO_EM_TORNO_DO_PONTO = re.compile(r"\s*\.\s*")
FUNCAO = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
REFERENCIA = re.compile(r"\b[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_*-]+)*")

# Palavras que não são referência de contexto: literais da linguagem e as
# funções que o Actions oferece.
NAO_SAO_REFERENCIA = {
    "true", "false", "null", "and", "or", "not",
    "contains", "startsWith", "endsWith", "format", "join", "toJSON",
    "fromJSON", "hashFiles", "success", "always", "cancelled", "failure",
}


def referencia_segura(referencia: str) -> bool:
    """A regra é ALLOWLIST: passa o que se prova seguro, recusa o resto.

    🚨 **Por que invertida, e por que só na quinta rodada.** A cerca começou
    listando o que é perigoso, e acumulou NOVE bypass em quatro rodadas de
    revisão: índice no lugar de ponto, expressão partida entre linhas, escalar
    entre aspas, heredoc, `}}` dentro de string, `toJSON(github.event)`,
    `toJSON(github)`, `env.*` reinterpolado, `matrix.*` reinterpolado. Cada
    conserto fechava uma forma; a forma seguinte aparecia na revisão seguinte.

    Lista de perigos envelhece contra um adversário que tem a linguagem inteira.
    Allowlist inverte o ônus: **forma nova nasce recusada**, e quem quiser usá-la
    declara. O custo foi medido antes: a `main` tem **cinco** interpolações
    dentro de `run:`, e todas referenciam `github.repository` ou folha segura de
    evento.
    """
    if referencia in NAO_SAO_REFERENCIA:
        return True
    if referencia in CONTEXTOS_SEGUROS:
        return True
    if "*" in referencia:
        # 🚨 Curinga só passa sobre COLEÇÃO DECLARADA, e a lista é curta de
        # propósito. A rodada anterior soltou "curinga sobre caminho conhecido"
        # e isso foi REGRESSÃO: `github.event.deployment.*.id` atravessa o
        # `payload`, que é objeto livre, e escapava dos prefixos de autor
        # justamente por causa do `*`. Achado P1 da 8ª rodada da #245.
        #
        # Declarar as coleções é o mesmo princípio do resto da cerca: o que não
        # está escrito como seguro, é recusado.
        for colecao in COLECOES_TIPADAS:
            if referencia.startswith(colecao):
                return folha(referencia) in FOLHAS_SEGURAS
        return False
    if referencia.startswith("github.event."):
        # Entrada de dispatch é digitada por quem chama, qualquer que seja a
        # folha — um input chamado `id` carrega texto arbitrário.
        for prefixo in PREFIXOS_DE_AUTOR:
            if referencia.startswith(prefixo):
                return False
        return folha(referencia) in FOLHAS_SEGURAS
    for prefixo in PREFIXOS_SEGUROS:
        if referencia.startswith(prefixo):
            return True
    return bool(ESTADO_TIPADO.match(referencia))


def motivos(expressao: str):
    """Por que esta expressão é perigosa — lista vazia quer dizer que não é."""
    # A ORDEM importa, e a inversão dela foi bypass: `normalizar` primeiro, para
    # `inputs['id']` virar `inputs.id` ANTES de o literal `'id'` ser apagado.
    texto = normalizar(" ".join(expressao.split()))
    texto = LITERAL.sub(" '' ", texto)
    # `github . event . title` é válido para o Actions — os espaços somem aqui,
    # ou a referência não seria reconhecida.
    texto = ESPACO_EM_TORNO_DO_PONTO.sub(".", texto)

    funcoes = set(FUNCAO.findall(texto))
    for referencia in REFERENCIA.findall(texto):
        if referencia in funcoes and "." not in referencia:
            continue
        if referencia_segura(referencia):
            continue
        yield (
            f"«{referencia}» não está na lista do que se prova seguro dentro de "
            f"`run:`. Se o valor vem do autor da PR, ele é colado no TEXTO do "
            f"script. Passe por `env:` e leia como variável do SHELL (\"$NOME\")"
        )


def achados_do_texto(texto_do_arquivo: str):
    """Devolve (linha, expressão, motivo) de cada interpolação perigosa em `run:`."""
    for linha_inicial, script in escalares_run(texto_do_arquivo):
        for offset, conteudo in expressoes(script):
            expressao = " ".join(conteudo.split())
            # A linha do achado é a do CONTEÚDO do escalar (`_linha_inicial`,
            # que desconta o indicador do bloco) mais o deslocamento dentro
            # dele — exato no bloco literal e em escalar de uma linha só, que
            # são as formas em que `run:` se escreve. Segue aproximado no
            # dobrado e no plano de várias linhas, onde o próprio YAML já
            # descartou as quebras antes de a cerca ver o valor.
            linha = linha_inicial + script[:offset].count("\n")
            for motivo in motivos(conteudo):
                yield linha, expressao, motivo


def achados_do_arquivo(caminho: pathlib.Path):
    return achados_do_texto(caminho.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# Autoteste — a cerca guardando a si mesma
#
# Cada caso abaixo é um achado real da revisão da PR #245 ou uma forma que o
# sacrifício documentado exercitou. Roda no CI antes da varredura: cerca de
# segurança que ninguém verifica é a que passa a ser contornada em silêncio, e
# das três falhas que a revisão achou, DUAS eram bypass e uma era falso
# positivo — as duas categorias precisam de caso.
# --------------------------------------------------------------------------
CASOS = [
    (
        "sintaxe de índice contorna a forma com ponto (P1 da #245)",
        "steps:\n  - name: x\n    run: echo ${{ github['event'].pull_request.title }}\n",
        1,
    ),
    (
        "índice no meio do caminho também",
        "steps:\n  - run: echo ${{ github.event['pull_request']['title'] }}\n",
        1,
    ),
    (
        "entrada de workflow_dispatch com folha de nome seguro (#245)",
        "steps:\n  - run: echo ${{ github.event.inputs.id }}\n",
        1,
    ),
    (
        "título por forma com ponto — o sacrifício documentado",
        "steps:\n  - run: echo ${{ github.event.pull_request.title }}\n",
        1,
    ),
    (
        "nome de branch da PR",
        "steps:\n  - run: echo ${{ github.head_ref }}\n",
        1,
    ),
    (
        "SHA e número passam — reprová-los seria falso positivo na main",
        "steps:\n  - run: |\n"
        "      BASE=\"${{ github.event.pull_request.base.sha || github.event.before }}\"\n"
        "      echo ${{ github.event.pull_request.number }}\n",
        0,
    ),
    (
        "`env:` irmão de `- run: |` NÃO é parte do bloco (#245)",
        "steps:\n  - run: |\n      echo \"$TITULO\"\n"
        "    env:\n      TITULO: ${{ github.event.pull_request.title }}\n",
        0,
    ),
    (
        "escalar DOBRADO com a expressão partida entre linhas (P1, 2ª rodada)",
        "steps:\n  - run: >-\n      echo \"${{\n      github.event.pull_request.title }}\"\n",
        1,
    ),
    (
        "escalar LITERAL com a expressão partida — mesma classe",
        "steps:\n  - run: |\n      echo \"${{\n        github.event.pull_request.body }}\"\n",
        1,
    ),
    (
        "escalar ENTRE ASPAS continuando na linha seguinte (P1, 3ª rodada)",
        "steps:\n  - run: \"echo '${{\n      github.event.pull_request.title }}'\"\n",
        1,
    ),
    (
        "escalar SIMPLES continuando na linha seguinte — mesma classe",
        "steps:\n  - run: echo ${{\n      github.event.pull_request.body }}\n",
        1,
    ),
    (
        "heredoc com `run:` dentro não desliga o rastreio do bloco (P1, 3ª rodada)",
        "steps:\n  - run: |\n      cat <<'EOF' > outro.yml\n      run: harmless\n      EOF\n"
        "      echo ${{ github.event.pull_request.title }}\n",
        1,
    ),
    (
        "bloco partido que é SEGURO continua passando",
        "steps:\n  - run: >-\n      echo ${{\n      github.event.pull_request.number }}\n",
        0,
    ),
    (
        "chave `run` fora de mapeamento de passo não é confundida com script",
        "steps:\n  - name: x\n    with:\n      texto: ${{ github.event.pull_request.title }}\n",
        0,
    ),
    (
        "`}}` dentro de string não fecha a expressão (P1, 3ª rodada)",
        "steps:\n  - run: echo ${{ format('{{oi}} {0}', github.event.pull_request.title) }}\n",
        1,
    ),
    (
        "payload inteiro serializado — `toJSON(github.event)` (P1, 3ª rodada)",
        "steps:\n  - run: echo ${{ toJSON(github.event) }}\n",
        1,
    ),
    (
        "input de action chamado `run` NÃO é script de shell (3ª rodada)",
        "steps:\n  - uses: alguem/acao@v1\n    with:\n"
        "      run: ${{ github.event.pull_request.title }}\n",
        0,
    ),
    (
        "contexto `github` INTEIRO serializado (P1, 4ª rodada)",
        "steps:\n  - run: echo ${{ toJSON(github) }}\n",
        1,
    ),
    (
        "literal com CARA de contexto é texto constante (4ª rodada)",
        "steps:\n  - run: echo ${{ 'github.event.pull_request.title' }}\n",
        0,
    ),
    (
        "`env.*` dentro de `run:` reinterpola o valor no texto (P1, 4ª rodada)",
        "steps:\n  - run: echo \"${{ env.TITULO }}\"\n",
        1,
    ),
    (
        "campos seguros do contexto `github` continuam passando",
        "steps:\n  - run: echo ${{ github.sha }} ${{ github.repository }} ${{ github.run_id }}\n",
        0,
    ),
    (
        "índice com literal: `inputs['id']` não pode virar acesso vazio (P1, 5ª rodada)",
        "steps:\n  - run: echo ${{ inputs['id'] }}\n",
        1,
    ),
    (
        "`env['TITULO']` pela mesma razão",
        "steps:\n  - run: echo ${{ env['TITULO'] }}\n",
        1,
    ),
    (
        "espaço em torno do ponto não esconde a referência (P1, 5ª rodada)",
        "steps:\n  - run: echo ${{ github . event . pull_request . title }}\n",
        1,
    ),
    (
        "`matrix.*` reinterpola valor que pode ter vindo do evento (P1, 5ª rodada)",
        "steps:\n  - run: echo \"${{ matrix.command }}\"\n",
        1,
    ),
    (
        "login de quem abriu a PR é texto de autor",
        "steps:\n  - run: echo \"${{ github.actor }}\"\n",
        1,
    ),
    (
        "e o ator que disparou também",
        "steps:\n  - run: echo \"${{ github.triggering_actor }}\"\n",
        1,
    ),
    (
        "`github.ref_name` deriva do nome da branch",
        "steps:\n  - run: echo \"${{ github.ref_name }}\"\n",
        1,
    ),
    (
        "`github.ref` carrega nome de branch, que aceita metacaractere (5ª rodada)",
        "steps:\n  - run: echo \"${{ github.ref }}\"\n",
        1,
    ),
    (
        "`github.event.action` NÃO é enum em repository_dispatch (5ª rodada)",
        "steps:\n  - run: echo ${{ github.event.action }}\n",
        1,
    ),
    (
        "saída de passo anterior também pode ter copiado texto de autor",
        "steps:\n  - run: echo ${{ steps.x.outputs.y }}\n",
        1,
    ),
    (
        "filtro de objeto alcança entrada de dispatch (P1, 6ª rodada)",
        "steps:\n  - run: echo ${{ join(github.event.*.id, ' ') }}\n",
        1,
    ),
    (
        "`github.workflow` é nome escolhido pela PR (P1, 6ª rodada)",
        "steps:\n  - run: echo \"${{ github.workflow }}\"\n",
        1,
    ),
    (
        "hífen em segmento de contexto seguro não vira falso positivo (6ª rodada)",
        "steps:\n  - run: echo ${{ strategy.job-index }} ${{ strategy.fail-fast }}\n",
        0,
    ),
    (
        "corpo de repository_dispatch com folha de nome seguro (8ª rodada)",
        "steps:\n  - run: echo ${{ github.event.client_payload.id }}\n",
        1,
    ),
    (
        "payload no deployment_status — o prefixo que a meta-checagem denunciou",
        "steps:\n  - run: echo ${{ github.event.deployment_status.deployment.payload.id }}\n",
        1,
    ),
    (
        "payload de deployment com folha de nome seguro (P1, 7ª rodada)",
        "steps:\n  - run: echo ${{ github.event.deployment.payload.id }}\n",
        1,
    ),
    (
        "índice numérico não quebra a referência (8ª rodada)",
        "steps:\n  - run: echo ${{ github.event.pull_request.labels[0].id }}\n",
        0,
    ),
    (
        "e a folha perigosa continua recusada mesmo através do índice",
        "steps:\n  - run: echo ${{ github.event.pull_request.labels[0].name }}\n",
        1,
    ),
    (
        "curinga sobre caminho CONHECIDO com folha segura passa (8ª rodada)",
        "steps:\n  - run: echo ${{ join(github.event.pull_request.labels.*.id, ',') }}\n",
        0,
    ),
    (
        "curinga por CIMA de payload livre recusa (P1, 8ª rodada)",
        "steps:\n  - run: echo ${{ join(github.event.deployment.*.id, ' ') }}\n",
        1,
    ),
    (
        "e curinga LIVRE continua recusado",
        "steps:\n  - run: echo ${{ join(github.event.*.id, ',') }}\n",
        1,
    ),
    (
        "estado gerado pelo runner é enum, não texto de autor (8ª rodada)",
        "steps:\n  - run: echo ${{ steps.compilar.outcome }} ${{ steps.compilar.conclusion }}"
        " ${{ needs.build.result }}\n",
        0,
    ),
    (
        "todo contexto declarado seguro passa — a outra metade da matriz",
        "steps:\n  - run: |\n"
        "      echo ${{ github.repository }} ${{ github.repository_owner }} ${{ github.sha }}\n"
        "      echo ${{ github.run_id }} ${{ github.run_number }} ${{ github.run_attempt }}\n"
        "      echo ${{ github.job }} ${{ github.event_name }} ${{ github.workspace }}\n"
        "      echo ${{ github.api_url }} ${{ github.server_url }}\n",
        0,
    ),
    (
        "e as famílias inteiras declaradas seguras também",
        "steps:\n  - run: |\n"
        "      echo ${{ runner.os }} ${{ job.status }} ${{ strategy.job-total }}\n"
        "      curl -H \"authorization: bearer ${{ secrets.UM_TOKEN }}\" https://exemplo.test\n",
        0,
    ),
    (
        "as folhas tipadas restantes do evento também passam",
        "steps:\n  - run: |\n"
        "      echo ${{ github.event.after }} ${{ github.event.pull_request.merged }}\n"
        "      echo ${{ github.event.pull_request.draft }} ${{ github.event.deleted }}\n",
        0,
    ),
    (
        "e o OUTPUT do mesmo passo continua recusado",
        "steps:\n  - run: echo ${{ steps.compilar.outputs.versao }}\n",
        1,
    ),
    (
        "o que a main usa de verdade continua passando",
        "steps:\n  - run: |\n      gh api repos/${{ github.repository }}/pulls\n"
        "      echo ${{ github.event.pull_request.number }}\n",
        0,
    ),
    (
        "`toJSON` de um campo seguro continua passando",
        "steps:\n  - run: echo ${{ toJSON(github.event.pull_request.number) }}\n",
        0,
    ),
]


ACAO_COMPOSTA = (
    "action composta local também é varrida (P1, 7ª rodada)",
    "runs:\n  using: composite\n  steps:\n"
    "    - run: echo ${{ github.event.pull_request.title }}\n      shell: bash\n",
    1,
)


DIRETORIOS_IGNORADOS = {".git", "node_modules"}


def deve_varrer(caminho: pathlib.Path) -> bool:
    """Comparação por COMPONENTE do caminho, não por substring.

    Achado P1 da 9ª rodada da #245: `".git/" not in str(p)` descartava uma
    action legítima em `.github/mynode_modules/` ou `vendor/repo.git/`, e o
    `run:` dela ficava fora da cerca — verde por não ter sido lido.
    """
    return DIRETORIOS_IGNORADOS.isdisjoint(caminho.parts)


CAMINHOS = [
    (".github/actions/x/action.yml", True),
    (".github/mynode_modules/action.yml", True),     # nome COLIDENTE, é legítimo
    ("vendor/repo.git/action.yml", True),
    ("node_modules/alguma/action.yml", False),
    (".git/modules/x/action.yml", False),
]

# 🚨 Casos de LINHA — quantidade certa com linha errada é anotação que manda o
# revisor para o lugar errado, e o achado promete arquivo e linha exatos. Cada
# ESTILO de escalar do YAML precisa de um caso: a meta-checagem abaixo lê o
# estilo do nó de cada texto e falha se algum dos cinco ficar sem cobertura —
# foi um estilo sem caso (o bloco literal) que deixou o erro de uma linha
# passar nove rodadas de revisão.
LINHAS = [
    (
        "bloco literal: a expressão está na linha do conteúdo, não na do `|`",
        "jobs:\n  x:\n    steps:\n"
        "      - run: |\n"
        "          echo ${{ github.event.pull_request.title }}\n",
        [5],
    ),
    (
        "bloco literal de várias linhas: cada achado na sua própria linha",
        "jobs:\n  x:\n    steps:\n"
        "      - run: |\n"
        "          echo um\n"
        "          echo ${{ github.event.pull_request.title }}\n"
        "          echo tres\n"
        "          echo ${{ github.head_ref }}\n",
        [6, 8],
    ),
    (
        "bloco literal com indicador de corte (`|-`) conta igual",
        "jobs:\n  x:\n    steps:\n"
        "      - run: |-\n"
        "          echo ${{ github.event.pull_request.body }}\n",
        [5],
    ),
    (
        "bloco dobrado: a primeira linha de conteúdo, não a do `>`",
        "jobs:\n  x:\n    steps:\n"
        "      - run: >\n"
        "          echo ${{ github.event.issue.title }}\n",
        [5],
    ),
    (
        "escalar plano na mesma linha do `run:`",
        "jobs:\n  x:\n    steps:\n"
        "      - run: echo ${{ github.event.comment.body }}\n",
        [4],
    ),
    (
        "escalar plano que começa na linha seguinte",
        "jobs:\n  x:\n    steps:\n"
        "      - run:\n"
        "          echo ${{ github.event.review.body }}\n",
        [5],
    ),
    (
        "escalar entre aspas duplas",
        "jobs:\n  x:\n    steps:\n"
        '      - run: "echo ${{ github.event.pull_request.head.label }}"\n',
        [4],
    ),
    (
        "escalar entre aspas simples",
        "jobs:\n  x:\n    steps:\n"
        "      - run: 'echo ${{ github.event.pull_request.head.ref }}'\n",
        [4],
    ),
    (
        "action composta: a linha também desconta o indicador do bloco",
        "runs:\n  using: composite\n  steps:\n"
        "    - shell: bash\n"
        "      run: |\n"
        "        echo ${{ github.event.pull_request.title }}\n",
        [6],
    ),
]

ESTILOS_DE_ESCALAR = ("|", ">", "'", '"', None)


def _estilos_dos_casos_de_linha():
    """Quais estilos de escalar os casos de LINHA realmente exercitam."""
    vistos = set()
    for _, texto, _ in LINHAS:
        raiz = yaml.compose(texto)
        for script in _nos_run(raiz):
            vistos.add(script.style)
    return vistos


def autoteste() -> int:
    """Roda os casos pelo CAMINHO REAL da varredura, não por uma cópia da lógica.

    ⚠️ A primeira versão desta função reimplementava a decisão de "é perigoso?"
    — e uma cópia da lógica passa verde enquanto o caminho real falha, que é o
    defeito exato que estes casos existem para pegar. Agora ela chama
    `achados_do_texto`, o mesmo que roda contra os workflows.
    """
    falhas = 0
    # A action composta não é embrulhada em `jobs:` — a estrutura dela é outra,
    # e é justamente isso que a fazia escapar.
    nome, texto, esperado = ACAO_COMPOSTA
    achados = {b for _, b, _ in achados_do_texto(texto)}
    if len(achados) != esperado:
        print(f"AUTOTESTE FALHOU: {nome}")
        print(f"  esperado {esperado} achado(s), veio {len(achados)}: {achados}")
        falhas = 1
    else:
        print(f"ok: {nome}")
    for nome, texto, esperado in CASOS:
        # Embrulha o trecho num workflow mínimo: desde a terceira rodada da
        # #245 a cerca só lê `jobs.*.steps[*].run`, e um caso solto passaria a
        # não ser lido — verde por não ser visto, que é o defeito que estes
        # casos existem para pegar.
        completo = "jobs:\n  x:\n" + textwrap.indent(texto, "    ")
        achados = {bruto for _, bruto, _ in achados_do_texto(completo)}
        if len(achados) != esperado:
            falhas += 1
            print(f"AUTOTESTE FALHOU: {nome}")
            print(f"  esperado {esperado} achado(s), veio {len(achados)}: {achados}")
        else:
            print(f"ok: {nome}")
    # 🚨 Meta-checagem: cada prefixo de autor precisa de PELO MENOS UM caso.
    # Achado da 8ª rodada da #245 — `client_payload` foi declarado e nunca
    # exercitado, então removê-lo por engano deixaria o autoteste verde e a
    # folha `id` voltaria a ser aceita. Somar o caso que faltava conserta uma
    # linha; esta checagem conserta a CLASSE, e falha sozinha quando alguém
    # declarar um prefixo novo sem cobri-lo.
    texto_dos_casos = " ".join(t for _, t, _ in CASOS) + ACAO_COMPOSTA[1]
    for prefixo in PREFIXOS_DE_AUTOR:
        if prefixo not in texto_dos_casos:
            falhas += 1
            print(f"AUTOTESTE FALHOU: o prefixo de autor «{prefixo}» não tem caso nenhum")
    for contexto in RECUSAS_DECLARADAS:
        if contexto not in texto_dos_casos:
            falhas += 1
            print(f"AUTOTESTE FALHOU: a recusa declarada «{contexto}» não tem caso nenhum")
    # E o outro lado da matriz: cada exceção da allowlist também precisa de
    # caso. Sem isto, apagar uma folha segura por engano mantém o autoteste
    # verde e o gate passa a REPROVAR o que ele mesmo declara tipado — falso
    # positivo silencioso, que é como uma cerca obrigatória vira alvo de pedido
    # de desligamento. Achado da 8ª rodada da #245.
    for folha_segura in FOLHAS_SEGURAS:
        if f".{folha_segura}" not in texto_dos_casos:
            falhas += 1
            print(f"AUTOTESTE FALHOU: a folha segura «{folha_segura}» não tem caso nenhum")
    for estado in ESTADOS_DE_PASSO + (ESTADO_DE_DEPENDENCIA,):
        if f".{estado}" not in texto_dos_casos:
            falhas += 1
            print(f"AUTOTESTE FALHOU: o estado tipado «{estado}» não tem caso nenhum")
    # ⚠️ O comentário acima prometia "cada exceção da allowlist" e a checagem
    # cobria só duas das cinco listas — achado da 8ª rodada da #245. Agora
    # enumera TODAS: contexto seguro, prefixo seguro e coleção tipada. Uma
    # permissão sem caso é uma permissão que alguém apaga sem o autoteste
    # reclamar, e aí o gate recusa workflow válido.
    for contexto in CONTEXTOS_SEGUROS:
        if contexto not in texto_dos_casos:
            falhas += 1
            print(f"AUTOTESTE FALHOU: o contexto seguro «{contexto}» não tem caso nenhum")
    for prefixo in PREFIXOS_SEGUROS:
        if prefixo not in texto_dos_casos:
            falhas += 1
            print(f"AUTOTESTE FALHOU: o prefixo seguro «{prefixo}» não tem caso nenhum")
    # A linha, não só a quantidade: `achados_do_texto` devolve (linha, ...) e
    # até a 10ª rodada NENHUM caso olhava para o primeiro elemento da tupla.
    for nome, texto, esperadas in LINHAS:
        vieram = [linha for linha, _, _ in achados_do_texto(texto)]
        if vieram != esperadas:
            falhas += 1
            print(f"AUTOTESTE FALHOU: {nome}")
            print(f"  linhas esperadas {esperadas}, vieram {vieram}")
        else:
            print(f"ok (linha): {nome}")
    for estilo in ESTILOS_DE_ESCALAR:
        if estilo not in _estilos_dos_casos_de_linha():
            falhas += 1
            print(f"AUTOTESTE FALHOU: o estilo de escalar «{estilo}» não tem caso de linha")
    for caminho, esperado in CAMINHOS:
        if deve_varrer(pathlib.Path(caminho)) != esperado:
            falhas += 1
            print(f"AUTOTESTE FALHOU: o filtro de caminho errou em «{caminho}»")
    for colecao in COLECOES_TIPADAS:
        if colecao not in texto_dos_casos:
            falhas += 1
            print(f"AUTOTESTE FALHOU: a coleção tipada «{colecao}» não tem caso nenhum")

    if falhas:
        print(f"\nERRO: {falhas} caso(s) de autoteste falharam — a cerca não faz o que diz.")
        return 1
    print(f"autoteste: {len(CASOS)} casos e {len(LINHAS)} de linha, todos como esperado.")
    return 0


def main() -> int:
    if "--autoteste" in sys.argv:
        return autoteste()

    raiz = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".github/workflows")
    # ⚠️ Sem `return` antecipado quando a pasta de workflows não existe: as
    # actions compostas seriam puladas junto, e um repositório que só tenha
    # action ficaria SEM cerca nenhuma passando verde. Achado do próprio ensaio
    # da 9ª rodada.
    arquivos = []
    if raiz.exists():
        arquivos = sorted(list(raiz.glob("*.yml")) + list(raiz.glob("*.yaml")))
    else:
        print(f"checa-interpolacao-em-run: {raiz} não existe — só as actions serão varridas.")
    # Manifestos de action composta, onde quer que estejam no repositório: o
    # `run:` deles executa com o mesmo contexto e estava fora do gate.
    # Comparação por COMPONENTE, não por substring no caminho inteiro: uma
    # action legítima em `.github/mynode_modules/` ou `vendor/repo.git/` era
    # descartada porque o NOME contém `node_modules` ou `.git`, e o `run:` dela
    # ficava fora da cerca. Achado P1 da 9ª rodada da #245.
    arquivos += sorted(p for p in pathlib.Path(".").rglob("action.y*ml") if deve_varrer(p))
    problemas = 0
    for caminho in arquivos:
        for numero, texto, motivo in achados_do_arquivo(caminho):
            problemas += 1
            print(f"::error file={caminho},line={numero}::interpolação em `run:`: {motivo}")
            print(f"  {caminho}:{numero}  ${{{{ {texto} }}}}")

    if problemas:
        print()
        print(f"ERRO: {problemas} interpolação(ões) de contexto controlável dentro de `run:`.")
        print("`${{ }}` é substituição de TEXTO antes do shell: o valor vira comando.")
        print("Passe por variável de ambiente — `env:` no passo, e `\"$VAR\"` no script.")
        print("Requisito SEG-CD-02 (spec de segurança do sisplo-erp). Fonte única desta cerca: Sisplo/.github, .github/scripts/checa-interpolacao-em-run.py.")
        return 1

    print(f"checa-interpolacao-em-run: {len(arquivos)} workflow(s) sem interpolação perigosa em `run:`.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
