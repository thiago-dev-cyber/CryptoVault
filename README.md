# CryptoVault

![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-em%20desenvolvimento-orange)

> ⚠️ **Este projeto está em desenvolvimento ativo e não está pronto para uso em produção.**
> Consulte a seção [Aviso de Segurança](#aviso-de-segurança) antes de qualquer uso.

Backup criptografado e versionado para qualquer provedor de cloud, escrito em Python puro. Inspirado no [Cryptomator](https://cryptomator.org/), mas com foco em backup programático e extensibilidade via drivers.

---

## Sumário

- [Status do projeto](#status-do-projeto)
- [O problema que resolve](#o-problema-que-resolve)
- [Visão geral da arquitetura](#visão-geral-da-arquitetura)
- [Como a criptografia funciona](#como-a-criptografia-funciona)
- [Como o versionamento funciona](#como-o-versionamento-funciona)
- [Como a deduplicação funciona](#como-a-deduplicação-funciona)
- [Como o manifest funciona](#como-o-manifest-funciona)
- [Sistema de drivers](#sistema-de-drivers)
- [Política de retenção](#política-de-retenção)
- [Estrutura do vault no disco/cloud](#estrutura-do-vault-no-discocloud)
- [Referência das classes](#referência-das-classes)
- [Aviso de segurança](#aviso-de-segurança)
- [Licença](#licença)

---

## Status do projeto

> **Em desenvolvimento — não use em produção.**

### ✅ Implementado

- `CryptoEngine` — cifra e decifra com AES-256-GCM + PBKDF2-SHA256


### 🔧 Em progresso



### 📋 Planejado / Falta implementar
- `Manifest` — índice cifrado de arquivos e versões (sem I/O próprio)
- `BaseDriver` (ABC) — interface abstrata de storage
- `LocalDriver` — driver local completo (leitura, escrita, listagem, deleção)
- Chunking de arquivos com SHA-256 por chunk
- Deduplicação baseada em hash de conteúdo
- Estrutura de versionamento no manifest
- `GoogleDriveDriver` — stub inicial, sem autenticação OAuth implementada
- Política de retenção (lógica definida, purge parcialmente implementado)
- `BackupManager.purge()` — identificação de chunks órfãos
- `MegaDriver` — não iniciado
- CLI (interface de linha de comando)
- Testes automatizados (unitários e de integração)
- Restauração parcial (por arquivo individual ou versão específica)
- Auditoria de segurança independente
- Documentação de instalação e uso (após estabilização da API)

---

## O problema que resolve

Ao enviar arquivos para a cloud, você geralmente enfrenta dois problemas:

1. **Privacidade**: o provedor (Google, Amazon, Mega...) pode ler seus arquivos, ou um vazamento pode expô-los.
2. **Histórico**: a maioria das soluções de backup mantém apenas a versão mais recente, ou cobra a mais por versionamento.

O CryptoVault resolve os dois: cifra tudo localmente antes de qualquer upload, e mantém um histórico completo de versões com deduplicação — sem depender de ferramentas do sistema operacional.

---

## Visão geral da arquitetura

```
┌─────────────────────────────────────────────────────────────┐
│                     BackupManager                           │
│   backup() ──► chunkify ──► encrypt ──► deduplicate ──► upload
│   restore() ◄── reconstruct ◄── decrypt ◄── download        │
│   purge()   ──► find orphan chunks ──► delete               │
└───────────┬──────────────────────────┬──────────────────────┘
            │                          │
   ┌─────────▼──────────┐   ┌──────────▼──────────┐
   │   CryptoEngine     │   │      Manifest        │
   │   AES-256-GCM      │   │   índice cifrado     │
   │   PBKDF2-SHA256    │   │   versionamento      │
   │   SHA-256 chunks   │   │   retenção           │
   └────────────────────┘   └─────────────────────┘
                                        │
   ┌─────────────────────────────────────▼──────────┐
   │                  BaseDriver (ABC)               │
   ├─────────────┬────────────────┬─────────────────┤
   │ LocalDriver │ GoogleDrive    │  MegaDriver      │
   │ (completo)  │ Driver (stub)  │  (não iniciado)  │
   └─────────────┴────────────────┴─────────────────┘
```

Cada camada tem uma responsabilidade única:

- **`CryptoEngine`** — cifra e decifra bytes. Não sabe onde os dados vão parar.
- **`Manifest`** — mantém o índice de arquivos e versões. Não faz I/O.
- **`BaseDriver`** — define a interface de storage. Não conhece criptografia.
- **`BackupManager`** — orquestra os três acima. É a única classe que faz tudo se comunicar.

**Dependência única:**

```
cryptography>=42.0.0
```

A biblioteca `cryptography` é a única dependência externa. Todo o resto (chunking, versionamento, manifest, drivers) usa a stdlib do Python. O projeto é compatível com Linux, macOS e Windows.

---

## Como a criptografia funciona

### Algoritmos utilizados

| Componente         | Algoritmo         | Parâmetros                          |
|--------------------|-------------------|-------------------------------------|
| Cifra simétrica    | AES-256-GCM       | chave de 256 bits, nonce de 96 bits |
| Derivação de chave | PBKDF2-SHA256     | 600.000 iterações, salt de 256 bits |
| Integridade        | GCM tag (128 bits)| autenticado por construção          |
| IDs de chunk       | SHA-256           | do conteúdo plaintext               |
| Hash de arquivo    | SHA-256           | do arquivo completo                 |

### Por que AES-256-GCM?

O GCM (Galois/Counter Mode) é um modo de operação **autenticado**: além de cifrar, ele gera uma tag de autenticação de 128 bits que detecta qualquer adulteração do ciphertext — mesmo que seja um único bit. Se o ciphertext for modificado (por corrupção de disco, ataque man-in-the-middle, ou qualquer outra causa), a decriptação falha com erro explícito. Não há possibilidade de decifrar um dado corrompido silenciosamente.

### Fluxo de cifra de um chunk

```
senha (str)
    │
    ▼
PBKDF2-SHA256 (600.000 iterações)
    ├── salt: os.urandom(32)   ← único por chunk
    └── chave AES-256 (32 bytes)
                │
                ▼
          AES-256-GCM
                ├── nonce: os.urandom(12)  ← único por chunk
                ├── plaintext: dados do chunk
                └── ciphertext + tag (16 bytes)
                          │
                          ▼
          blob armazenado no cloud:
          ┌──────────┬───────────┬──────────────────────┐
          │ salt     │  nonce    │ ciphertext + GCM tag  │
          │ 32 bytes │ 12 bytes  │ N + 16 bytes          │
          └──────────┴───────────┴──────────────────────┘
```

Cada chunk tem seu próprio `salt` e `nonce` gerados aleatoriamente via `os.urandom()`. Isso significa que dois chunks com conteúdo idêntico produzirão ciphertexts completamente diferentes. Não há como inferir se dois chunks têm o mesmo conteúdo olhando para os dados cifrados.

### Por que 600.000 iterações no PBKDF2?

A recomendação da OWASP para 2024 é de no mínimo 600.000 iterações de PBKDF2-SHA256. Esse número torna ataques de força bruta custosos: um atacante com hardware dedicado levaria tempo proporcional a centenas de anos para testar bilhões de senhas candidatas. O custo é pago uma vez por chunk no momento do backup/restore, o que é aceitável.

### O que o nonce previne

O nonce (number used once) garante que a mesma chave nunca cifre dois blocos de dados com o mesmo fluxo de keystream — o que quebraria a segurança do AES-CTR subjacente. Como cada chunk tem seu próprio salt (e portanto chave derivada diferente) além do nonce único, há dupla proteção contra reutilização de keystream.

---

## Aviso de Segurança

> ⚠️ **Leia antes de usar.**

Este projeto está em desenvolvimento ativo e **não foi submetido a auditoria de segurança independente**.

Embora utilize algoritmos modernos (AES-256-GCM, PBKDF2-SHA256) e a biblioteca `cryptography` — amplamente auditada pela comunidade — as seguintes ressalvas se aplicam:

- A integração entre os componentes pode conter falhas lógicas ainda não identificadas.
- Drivers de cloud (GoogleDrive, Mega) estão incompletos e não foram testados em cenários reais.
- Não há testes automatizados cobrindo casos extremos ou falhas de rede.
- A política de retenção e o `purge()` de chunks órfãos estão parcialmente implementados — uso incorreto pode causar perda de dados.

**Não utilize este projeto para armazenamento de dados sensíveis ou críticos sem validação independente.**

---

## Licença

Este projeto é distribuído sob a licença MIT.

Copyright (c) 2026 thiago-dev-cyber

Consulte o arquivo `LICENSE` para mais informações.