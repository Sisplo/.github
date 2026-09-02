# Sisplo/.github

Defaults de comunidade herdados automaticamente por todo repositório da organização Sisplo
que não tiver a própria versão de um destes arquivos: template de PR, formulários de issue.
Também hospeda os *reusable workflows* de CI mínimo que os repos chamam por tag.

**Este repo é público de propósito** — é a única visibilidade em que o GitHub propaga PR
template e issue forms para o resto da org (repo interno/privado serve reusable workflow
normalmente, mas os templates falham em silêncio). O conteúdo aqui é só scaffolding genérico:
nenhum segredo, nenhuma lógica de negócio, nenhum dado de cliente. Todo repositório de produto
da Sisplo continua privado, sem exceção — ver o handbook.

**O que NÃO herda daqui, mesmo público:** `CODEOWNERS`, `dependabot.yml` e `release.yml`
(notas de release automáticas) são per-repo por desenho do GitHub — não existe herança de
organização para eles. Ficam no [`Sisplo/template-repo`](https://github.com/Sisplo/template-repo),
copiados uma vez quando o repo nasce.

Processo completo, porquês e decisões datadas: [Sisplo/handbook](https://github.com/Sisplo/handbook).
