import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

async function validator(name) {
  const contract = JSON.parse(await readFile(new URL(`../tool-contracts/${name}.json`, import.meta.url), 'utf8'));
  const ajv = new Ajv({ strict: false });
  addFormats(ajv);
  return ajv.compile(contract.output_schema);
}

function result(tool, data, strategy) {
  return { ok: true, request_id: 'test-request', tool, result_class: 'SUCCEEDED', data,
    verification: { required: true, status: 'verified', strategy } };
}

test('visual click dispatch result satisfies its public contract', async () => {
  const validate = await validator('mac_ui_action');
  const output = result('mac_ui_action', { element_ref: 'element:test', action: 'click', accepted: true,
    job_id: `job:ui-action-${'a'.repeat(48)}`,
    reobserved: { role: 'VisualWindow', enabled: true, focused: true } }, 'visual_action_dispatch');
  assert.equal(validate(output), true, JSON.stringify(validate.errors));
  output.verification.dispatch_status = 'verified';
  output.verification.postcondition_status = 'unknown';
  assert.equal(validate(output), true, JSON.stringify(validate.errors));
  output.verification.postcondition_status = 'verified';
  assert.equal(validate(output), false, 'Dispatch evidence must not claim an intended UI postcondition');
  output.verification.postcondition_status = 'unknown';
  output.verification.strategy = 'unverified_strategy';
  assert.equal(validate(output), false);
});

test('typed input result accepts the Broker job identity and rejects unknown fields', async () => {
  const validate = await validator('mac_ui_type');
  const output = result('mac_ui_type', { element_ref: 'element:test', characters_accepted: 16,
    keys_accepted: [], submitted: false, focus_confirmed: true,
    job_id: `job:ui-type-${'b'.repeat(48)}`,
    reobserved: { role: 'AXTextField', focused: true, secure: false } }, 'focused_target_and_input_postcondition');
  assert.equal(validate(output), true, JSON.stringify(validate.errors));
  output.data.unexpected = true;
  assert.equal(validate(output), false);
});

test('visual action input contract accepts bounded negative global display coordinates', async () => {
  const contract = JSON.parse(await readFile(new URL('../tool-contracts/mac_ui_action.json', import.meta.url), 'utf8'));
  const validate = new Ajv({ strict: false }).compile(contract.input_schema);
  const action = { element_ref: 'element:test', action: 'click', x: -1100, y: 200 };
  assert.equal(validate(action), true, JSON.stringify(validate.errors));
  assert.equal(validate({ ...action, x: -20001 }), false);
});
