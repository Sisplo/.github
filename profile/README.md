# Sisplo

**A engenharia por trás do software.**

Esta é a organização onde vive o código da Sisplo. Ela pertence à **Sisplo Gestão de Ativos e Softwares**, a empresa do grupo que desenvolve o produto e detém a propriedade intelectual.

---

## O problema que nos ocupa

Uma empresa de construção deveria conseguir responder, a qualquer momento, duas perguntas: quanto esta obra já custou, e quanto ela ainda vai receber por ela.

A maior parte do setor não consegue. Não por falta de sistema — por falta de um sistema que entenda medição, aditivo, reajuste, retenção e saldo de contrato como o setor os pratica, e não como um ERP genérico os aproxima.

É essa distância que a Sisplo existe para fechar.

---

## O que construímos

### Sisplo ERP

Plataforma multi-tenant de gestão para a construção civil brasileira, do orçamento à entrega da obra.

Sete módulos — orçamento, planejamento, compras, medição, ordem de serviço, acompanhamento e gestão contratual — vendáveis separadamente e empacotados em seis edições, cada uma calibrada para um perfil do setor: o orçamentista autônomo, o construtor de obra própria, a construtora que executa para terceiros, a incorporadora, quem executa contrato público sob a Lei 14.133 e a empreiteira subcontratada.

O núcleo é o mesmo para todos. É o que permite atender perfis muito diferentes sem manter produtos paralelos.

### Turnaq

Plataforma de escritório virtual de agentes de IA, organizada como uma empresa — dono, setores e árvore de agentes, com memória viva em vaults de markdown versionados por git.

---

## Como construímos

A arquitetura é um **monolito modular** por escolha, não por acidente: núcleo único, banco único e transações fortes entre módulos. Multi-tenant em duas camadas — grupo econômico e CNPJ —, com isolamento no banco e trilha de auditoria imutável.

Algumas regras não são convenção, são cerca que quebra o build:

**Precisão** — tipos de ponto flutuante são proibidos em coluna financeira, e o CI reprova quem tentar. Num contrato de medição, um centavo de arredondamento não é bug: é disputa contratual.

**Spec antes do código** — todo módulo tem especificação escrita e revisada adversarialmente antes da primeira linha. As decisões de arquitetura ficam versionadas como ADRs, ao lado do código que elas explicam.

**Nada se edita retroativamente** — correção é evento novo, nunca alteração do registro anterior.

**Segredos** — todo push e todo pull request passam por duas varreduras que não pegam a mesma coisa: detecção por padrão e verificação de credencial viva contra o serviço de origem. Nenhuma das duas é opcional, e nenhuma delas depende de alguém lembrar de rodar.

**Cadeia de suprimentos** — actions de terceiros são restritas a um allowlist e fixadas por commit, nunca por tag móvel.

---

## Como trabalhamos

A operação é uma pessoa, com agentes de IA no lugar de um time de desenvolvimento.

É decisão estrutural, não escassez: mantém o custo próximo de zero durante a validação e faz o produto ser construído por quem conhece o domínio, em vez de traduzido por um time que precisa aprendê-lo. O limite é conhecido e declarado — essa configuração é excelente para construir e ruim para vender, e é por isso que a primeira contratação da casa é comercial, não engenharia.

O processo que sustenta isso é versionado como qualquer outro código: fluxo de trabalho, CI mínimo do primeiro dia, licenças permitidas e o que pode sair de casa.

---

## Repositórios

Os repositórios de produto são privados, sem exceção.

Este repositório [`.github`](https://github.com/Sisplo/.github) é público de propósito: é a única visibilidade em que o GitHub propaga templates de pull request e formulários de issue para o resto da organização. O conteúdo dele é scaffolding genérico — nenhum segredo, nenhuma lógica de negócio, nenhum dado de cliente.

---

## Segurança

Vulnerabilidades e suspeitas de exposição de credencial: **seguranca@sisplo.com**. A política completa está em [SECURITY.md](https://github.com/Sisplo/.github/blob/main/SECURITY.md).

---

## Contato

**Institucional** — ativos@sisplo.com

**Segurança** — seguranca@sisplo.com

**Site** — [sisplo.com](https://sisplo.com)

**LinkedIn** — [linkedin.com/company/sisplo](https://linkedin.com/company/sisplo)
