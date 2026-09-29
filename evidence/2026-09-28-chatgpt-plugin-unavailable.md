# ChatGPT Mac Operator GUI availability investigation

Status: failure boundary identified; platform root cause unresolved.
Date: 2026-09-28 (Asia/Kuala_Lumpur).

## Verified findings

- The previously connected Mac Operator GUI detail page now returns `Plugin not found` after a reload.
- Exact plugin reference: `plugin_asdk_app_6ab9ea7ca0d88191a04d694e34d42467`.
- The plugin metadata tool independently returned HTTP 404 / NOT_FOUND for that reference. Its editable-plugin scope means this result alone is not proof of deletion.
- Personal directory search for Mac Operator returned no result. Other personal plugins remain visible in the same signed-in account. General plugin search likewise did not find it.
- The existing Mac Screenshot Request conversation could not discover mac_app_focus or mac_ui_observe. Its first attempted function name was invalid; discovery subsequently found no callable tool. Neither attempt reached Broker execution.
- Both GUI-capable OAuth grants in the local Auth database remain unrevoked and unexpired. Both associated dynamic clients still exist, with no near-term client expiry.
- PM2 reports mac-operator-personal online. Public OAuth authorization-server and protected-resource metadata returned 200. Unauthenticated /mcp returned the expected 401 invalid_token / Missing Authorization header.
- Endpoint probes used an explicit Mac-Operator-Healthcheck User-Agent. Initial default Python-agent requests returned 403. This variation is not evidence that ChatGPT traffic is blocked, and it does not establish the cause of the plugin detail 404.
- Prior native active-window capture was verified. This investigation did not repeat or claim ChatGPT end-to-end screenshot success.

## Conclusion and limits

Current evidence identifies unavailable ChatGPT plugin lookup/tool routing as the immediate blocker. It does not support an expired Mac consent, absent DCR client, or offline Mac service as the immediate cause. Plugin deletion, access filtering, migration, and a platform defect cannot be distinguished without ChatGPT-side audit data. No claim is made about who removed the plugin or whether it was actually deleted.

No accounts, permissions, server code, grants, or plugin registrations were changed during this investigation. No support message was sent.

## Prepared support request

Subject: Previously connected personal MCP plugin now returns Plugin not found

A personal Mac Operator GUI plugin was created and connected on 2026-09-28. The UI previously displayed a Primary connected account and 37 tools. It later became unavailable in the personal directory and tool discovery. Reloading its original detail URL returns Plugin not found; a plugin metadata lookup also returns NOT_FOUND.

Plugin reference: plugin_asdk_app_6ab9ea7ca0d88191a04d694e34d42467
Detail URL: https://chatgpt.com/plugins/plugin_asdk_app_6ab9ea7ca0d88191a04d694e34d42467
MCP URL: https://mac.yapweijun1996.com/mcp

The service is online; OAuth metadata responds; both relevant GUI grants and dynamic client registrations remain valid on the server. Other personal plugins are still visible. No new screenshot request reached the Broker when the conversation failed tool discovery.

Please check this plugin's lifecycle, visibility/access and migration records, including any deletion or restriction event and its timestamp. Can the original plugin registration be restored without creating another OAuth client? Please distinguish plugin lookup failure from OAuth token failure.

Evidence available: before/after plugin screenshots, conversation transcript, sanitized server checks. No credentials or tokens are included.

## Reference

Official troubleshooting recommends separating server and ChatGPT client failures and providing logs, transcript and screenshots for unresolved issues:
https://developers.openai.com/plugins/deploy/troubleshooting


## Support submission (2026-09-29, Asia/Kuala_Lumpur)

After the owner completed passkey verification, submitted the authorized sanitized incident description through the signed-in OpenAI Help Center support chat. The message included the exact plugin reference, endpoint, historical checks and request for lifecycle/access investigation and restoration. No passwords, tokens, raw logs or screenshots were uploaded.

The support chat explicitly replied: "Escalated to a support specialist; You can expect a response in the coming days. Replies will also be sent via email. You can add additional comments to this conversation if needed." No case number was displayed. Submission and escalation are verified; platform root cause and restoration remain pending.

Confirmation screenshot: openai-support-escalated.png in the current chat visualization directory. The support tab was retained. No recurring follow-up or email monitoring was configured.
