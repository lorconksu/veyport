import { execFileSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { execPath } from 'node:process'
import { describe, expect, it } from 'vitest'

// Resolve through ESLint's Ajv, rather than a potentially unrelated root package.
const eslintRequire = createRequire(createRequire(import.meta.url).resolve('eslint'))
const ajvPath = eslintRequire.resolve('ajv')
const ajvRequire = createRequire(ajvPath)
const childSetup = `
  const assert = require('node:assert/strict');
  const { createRequire } = require('node:module');
  const ajvRequire = createRequire(${JSON.stringify(ajvPath)});
  const URI = ajvRequire('uri-js');
`

function runBounded(script: string) {
  return execFileSync(execPath, ['-e', childSetup + script], {
    timeout: 3000,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  })
}

describe('ESLint Ajv URI dependency', () => {
  it('uses the qualified fast-uri implementation inside Ajv', () => {
    expect(ajvRequire('uri-js/package.json')).toMatchObject({ name: 'fast-uri', version: '4.2.3' })
  })

  it('normalizes and resolves Unicode line separators within a subprocess deadline', () => {
    expect(runBounded(`
      for (const [character, encoded] of [['\u2028', '%E2%80%A8'], ['\u2029', '%E2%80%A9']]) {
        for (const options of [{}, { iri: true }]) {
          assert.equal(URI.normalize('https://example.test/a/' + character + '/b', options),
            'https://example.test/a/' + encoded + '/b');
          assert.equal(URI.resolve('https://example.test/a/root.json', character + '/b', options),
            'https://example.test/a/' + encoded + '/b');
        }
      }
      console.log('completed');
    `).trim()).toBe('completed')
  })

  it('preserves draft04 validation with relative, external and fragment references', () => {
    expect(runBounded(`
      const Ajv = require(${JSON.stringify(ajvPath)});
      const draft04 = ajvRequire('ajv/lib/refs/json-schema-draft-04.json');
      for (const schemaId of ['id', '$id']) {
        const ajv = new Ajv({ meta: false, schemaId: 'auto', allErrors: true });
        ajv.addMetaSchema(draft04);
        ajv.addSchema({
          [schemaId]: 'https://example.test/rules/definitions.json',
          definitions: { count: { type: 'integer', minimum: 0, maximum: 10, exclusiveMaximum: true } },
        });
        const validate = ajv.compile({
          $schema: 'http://json-schema.org/draft-04/schema#',
          [schemaId]: 'https://example.test/rules/options.json',
          type: 'object',
          properties: {
            count: { $ref: './definitions.json#/definitions/count' },
            external: { $ref: 'https://example.test/rules/definitions.json#/definitions/count' },
            label: { $ref: '#/definitions/label' },
          },
          definitions: { label: { type: 'string', minLength: 1 } },
          required: ['count', 'external', 'label'],
          additionalProperties: false,
        });
        assert.equal(validate({ count: 0, external: 9, label: 'rule' }), true);
        for (const data of [
          { count: 10, external: 9, label: 'rule' },
          { count: 1, external: '9', label: 'rule' },
          { count: 1, external: 9, label: '' },
          { count: 1, label: 'rule' },
          { count: 1, external: 9, label: 'rule', extra: true },
        ]) assert.equal(validate(data), false);
      }
      console.log('completed');
    `).trim()).toBe('completed')
  })
})
