# Catchy

Self-hosted hook catcher with multi-protocol API (gRPC, gRPC-Web, Connect, REST).

## Services

`catchy.v1.HookService` — list and get caught hooks, report how they were processed, and delete them.

| RPC | Method | Path |
|---|---|---|
| `ListHooks` | `GET` | `/v1/hooks` |
| `GetHook` | `GET` | `/v1/hooks/{id}` |
| `ProcessHook` | `POST` | `/v1/hooks/{id}/process` |
| `FailHook` | `POST` | `/v1/hooks/{id}/fail` |
| `DiscardHook` | `POST` | `/v1/hooks/{id}/discard` |
| `RetryHook` | `POST` | `/v1/hooks/{id}/retry` |
| `DeleteHook` | `DELETE` | `/v1/hooks/{id}` |

`catchy.v1.ChannelService` — list, get, pause, resume, and delete channels.

| RPC | Method | Path |
|---|---|---|
| `ListChannels` | `GET` | `/v1/channels` |
| `GetChannel` | `GET` | `/v1/channels/{name}` |
| `PauseChannel` | `POST` | `/v1/channels/{name}/pause` |
| `ResumeChannel` | `POST` | `/v1/channels/{name}/resume` |
| `DeleteChannel` | `DELETE` | `/v1/channels/{name}` |

## Links

- [GitHub](https://github.com/catchysh/catchy)
