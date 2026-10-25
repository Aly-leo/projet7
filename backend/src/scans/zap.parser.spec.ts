import { describe, expect, it } from 'vitest';
import { fingerprintOf, jsonDepth, parseZapReport, toPlainText, ZapImportError } from './zap.parser.js';

const file = (obj: unknown, name = 'r.json', mimetype = 'application/json') => ({
  originalname: name,
  mimetype,
  buffer: Buffer.from(typeof obj === 'string' ? obj : JSON.stringify(obj)),
});
const alert = (over: Record<string, unknown> = {}) => ({ pluginid: '1', alert: 'Titre', riskcode: '2', confidence: '2', count: '3', cweid: '79', desc: '<p>Bonjour</p>', ...over });
const parse = (alerts: unknown[], limits = { maxAlerts: 100 }) => parseZapReport(file({ site: [{ alerts }] }), limits);
const fails = (fn: () => unknown, status: number) => {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(ZapImportError);
    expect((e as ZapImportError).status).toBe(status);
    return;
  }
  throw new Error('aucune erreur levée');
};

describe('Parseur de rapports ZAP', () => {
  it('traite cweid -1, 0 ou vide comme « pas de CWE »', () => {
    const { findings } = parse([alert({ cweid: '-1', pluginid: '1' }), alert({ cweid: '0', pluginid: '2', alert: 'B' }), alert({ cweid: '', pluginid: '3', alert: 'C' }), alert({ pluginid: '4', alert: 'D', cweid: undefined })]);
    expect(findings.map((f) => f.cweId)).toEqual([null, null, null, null]);
  });

  it('tolère les champs absents et normalise riskcode, confiance, instances', () => {
    const { findings } = parse([{ pluginid: 7, alert: 'Minimal' }]);
    expect(findings[0]).toMatchObject({ severity: 0, confidence: null, instancesCount: 1, sampleUrls: [], description: '' });
  });

  it('convertit le HTML en texte brut', () => {
    const { findings } = parse([alert({ desc: '<p>Un <b>test</b></p><script>alert(1)</script><img src=x onerror=alert(2)><a href="javascript:alert(3)">lien</a>' })]);
    expect(findings[0]!.description).toBe('Un test\nlien');
    expect(toPlainText('<p>a &lt; b</p>', 50)).toBe('a < b');
  });

  it('plafonne à 50 URL d\'exemple et fusionne les alertes dupliquées', () => {
    const instances = Array.from({ length: 80 }, (_, i) => ({ uri: `http://t/${i}` }));
    const { findings } = parse([alert({ instances, count: '80' }), alert({ instances: [{ uri: 'http://t/autre' }], count: '2' })]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.sampleUrls).toHaveLength(50);
    expect(findings[0]!.instancesCount).toBe(82);
  });

  it('applique le plafond d\'alertes (422)', () => {
    fails(() => parse(Array.from({ length: 6 }, (_, i) => alert({ pluginid: String(i) })), { maxAlerts: 5 }), 422);
  });

  it('refuse type, extension, contenu et JSON invalides', () => {
    fails(() => parseZapReport(file({ site: [] }, 'r.json', 'text/plain'), { maxAlerts: 5 }), 415);
    fails(() => parseZapReport(file({ site: [] }, 'r.xml'), { maxAlerts: 5 }), 415);
    fails(() => parseZapReport(file('[1,2]'), { maxAlerts: 5 }), 415);
    fails(() => parseZapReport(file('{"site": [ '), { maxAlerts: 5 }), 400);
    fails(() => parseZapReport(file('{"site":[],"__proto__":{"x":1}}'), { maxAlerts: 5 }), 400);
    fails(() => parseZapReport(file('{"a":{"constructor":{"prototype":{}}},"site":[]}'), { maxAlerts: 5 }), 400);
    fails(() => parseZapReport(file({ site: 'nope' }), { maxAlerts: 5 }), 422);
    fails(() => parseZapReport(file(`{"site":${'['.repeat(40)}${']'.repeat(40)}}`), { maxAlerts: 5 }), 422);
  });

  it('accepte un BOM UTF-8', () => {
    const buf = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify({ site: [] }))]);
    expect(parseZapReport({ originalname: 'r.json', mimetype: 'application/json', buffer: buf }, { maxAlerts: 5 }).findings).toEqual([]);
  });

  it('mesure la profondeur sans être trompé par les chaînes', () => {
    expect(jsonDepth('{"a":"[[[[[[["}', 20)).toBe(1);
    expect(jsonDepth('{"a":[{"b":[1]}]}', 20)).toBe(4);
  });

  it('calcule une empreinte stable, indépendante de la casse et des espaces du titre', () => {
    const a = fingerprintOf('app', { pluginId: '1', cweId: 79, title: 'Cross  Site Scripting' });
    expect(a).toBe(fingerprintOf('app', { pluginId: '1', cweId: 79, title: ' cross site scripting ' }));
    expect(a).not.toBe(fingerprintOf('autre', { pluginId: '1', cweId: 79, title: 'Cross Site Scripting' }));
  });
});
