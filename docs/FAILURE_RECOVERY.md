# Recuperacao de falhas

## Arquivos

```text
video.mp4          arquivo oficialmente ativo
video_new.tmp      download novo, nunca usado pelo player
video_backup.mp4   ultima versao funcional conhecida
```

## Regra absoluta

Nunca apagar ou sobrescrever uma versao funcional sem ter outra versao comprovada. `video_new.tmp` nunca vira fonte de playback diretamente.

## Inicializacao deterministica

Antes de iniciar update, o atualizador executa conciliacao:

### Caso A

```text
video.mp4 existe
video_backup.mp4 nao existe
```

Estado normal. Apagar `video_new.tmp` se nao houver download retomavel seguro.

### Caso B

```text
video.mp4 existe
video_backup.mp4 existe
```

Se estado persistido indica `WAITING_PLAYBACK` ou `PLAYER_RESTARTING`, aguardar/solicitar confirmacao do novo player. Se falhar ou expirar, rollback. Se sucesso ja confirmado, manter backup por periodo configurado.

### Caso C

```text
video.mp4 nao existe
video_backup.mp4 existe
```

Restaurar backup imediatamente para `video.mp4` antes de qualquer atualizacao.

### Caso D

```text
video.mp4 existe
video_new.tmp existe
```

Tratar `video_new.tmp` como download interrompido ou pendente. Se nao houver metadados completos para retomar com seguranca, apagar tmp e preservar `video.mp4`.

### Caso E

```text
video.mp4 nao existe
video_new.tmp existe
video_backup.mp4 existe
```

Priorizar backup: mover `video_backup.mp4` para `video.mp4`; apagar ou isolar tmp.

## Queda durante download

Resultado esperado ao religar:

- `video.mp4` intacto;
- `video_new.tmp` incompleto;
- player abre video antigo;
- atualizador remove ou reinicia tmp;
- nenhum restart do player.

## Queda durante instalacao

Instalacao sera feita com renames no mesmo diretorio/filesystem:

```text
video.mp4 -> video_backup.mp4
video_new.tmp -> video.mp4
```

Ao religar, a conciliacao de arquivos decide:

- se falta `video.mp4` e existe backup, restaura backup;
- se existe `video.mp4` e backup durante estado pendente, tenta confirmar playback do novo;
- se playback novo falha, rollback.

## Falha de playback apos troca

Fluxo:

```text
WAITING_PLAYBACK
-> timeout ou erro do player
-> ROLLBACK
-> remover video.mp4 problematico
-> video_backup.mp4 -> video.mp4
-> reiniciar processo Player
-> confirmar playback antigo
-> UPDATE_FAILED_ROLLED_BACK
```

## Logs

Logs com rotacao e limite de tamanho. Campos:

```text
timestamp
state
version
event
error
```

Exemplo:

```text
14:02 UPDATE_FOUND version=12
14:02 DOWNLOAD_STARTED
14:05 DOWNLOAD_COMPLETE
14:05 SHA256_OK
14:05 INSTALL_STARTED
14:05 PLAYER_RESTART_REQUESTED
14:05 PLAYER_STARTED
14:05 PLAYBACK_CONFIRMED
14:05 UPDATE_SUCCESS version=12
```
