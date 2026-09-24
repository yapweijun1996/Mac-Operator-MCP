# ChatGPT R1 post-cutover smoke evidence

Date: 2026-09-21

## Scope

This is a client-side read-only smoke test after the loopback-enabled r1f
snapshot became the live PM2 deployment. It does not request or enable a
mutation, GUI, destructive, task, or privileged capability.

## Visible ChatGPT result

The installed `Mac Operator MCP R1 Read Only` app was selected in ChatGPT and
the following prompt was sent:

```text
Run mac_health with include_components=false. Report only the bounded result and whether the call succeeded.
```

The visible result was:

- call succeeded: yes;
- overall status: `healthy`;
- components: omitted;
- warnings: none;
- truncated: false.

## Origin readback

The protected PM2 output recorded the same client flow after cutover:

- `/token`: HTTP 200, client category `openai`;
- `/oauth/status`: HTTP 200;
- `/mcp` `tools/call`: HTTP 200, authenticated client category `openai`.

No credentials, access tokens, or response secrets were recorded in this
evidence.

## Conclusion

The owner-approved ChatGPT R1 app can still reach and execute a bounded read
call through the current r1f deployment after the loopback status-channel
rollout.
