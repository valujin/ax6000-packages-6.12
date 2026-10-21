'use strict';
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(process.argv[2], 'utf8');
const writes = [];
const loads = [];
function Value() { this.keylist = []; this.vallist = []; }
Value.prototype.value = function(key, label) {
  // LuCI Value.value appends; it does not silently deduplicate keys.
  this.keylist.push(String(key)); this.vallist.push(String(label ?? key));
};
Value.prototype.load = function(section) { loads.push(section); return this.values[section]; };
Value.prototype.write = function(section, value) { writes.push([section, 'country', value]); this.values[section] = value; };
Value.prototype.renderWidget = function() { return 'value'; };
Value.extend = function(methods) {
  function Child() { Value.call(this); }
  Child.prototype = Object.create(Value.prototype);
  Object.assign(Child.prototype, methods);
  return Child;
};
const context = vm.createContext({
  form: { Value, ListValue: { prototype: { renderWidget: () => 'list' } } },
  rpc: { declare: () => function() { return Promise.resolve(this.countrylist); } },
  L: { bind: (fn, self) => fn.bind(self) },
  _: value => value,
});
vm.runInContext("String.prototype.format = function(...args) { let n = 0; return this.replace(/%s/g, () => args[n++]); };", context);
const start = source.indexOf('var CBIWifiCountryValue = form.Value.extend({');
const end = source.indexOf('\nreturn view.extend({', start);
assert(start >= 0 && end > start, 'actual country option class must exist');
vm.runInContext(source.slice(start, end), context);
const Country = context.CBIWifiCountryValue;
const vendorStart = source.indexOf("else if (hwtype == 'mtwifi') {");
const vendorEnd = source.indexOf('\n\n', vendorStart);
assert(vendorStart >= 0 && vendorEnd > vendorStart);
const vendorSetup = source.slice(source.indexOf('\n', vendorStart), vendorEnd).trim();
function option(vendor, countries, section, values) {
  let result;
  if (vendor) {
    // Execute the actual mtwifi UI option-construction statements.
    context.ss = { taboption: (tab, cls, name) => {
      assert.equal(tab, 'advanced'); assert.equal(name, 'country');
      result = new cls(); return result;
    } };
    context.radioNet = { getWifiDeviceName: () => section };
    vm.runInContext('var o;\n' + vendorSetup, context);
    assert.equal(result.wifiNetwork.getWifiDeviceName(), section);
  } else { result = new Country(); }
  result.countrylist = countries;
  result.values = values;
  return result;
}
(async function() {
  // Parse the complete changed source, without executing browser UI or target code.
  new vm.Script('(function() {\n' + source + '\n})');
  const standard = [ { iso3166: 'CN', country: 'China' }, { iso3166: 'US', country: 'United States' } ];
  for (const countries of [standard, [], null, [...standard, { iso3166: 'DB', country: 'Debug' }]]) {
    const values = { MT7986_1_2: 'CN', arbitrary_radio_5g: 'US' };
    const first = option(true, countries, 'MT7986_1_2', values);
    const second = option(true, countries, 'arbitrary_radio_5g', values);
    writes.length = 0;
    assert.equal(await first.load('MT7986_1_2'), 'CN');
    assert.equal(await second.load('arbitrary_radio_5g'), 'US');
    assert.deepEqual(writes, [], 'loading options must not write any radio');
    assert.equal(first.keylist.filter(x => x === 'DB').length, 1);
    assert.equal(first.keylist[0], '', 'empty RPC lists retain driver default before DB');
    assert.equal(first.renderWidget('MT7986_1_2', 0, 'CN'), Array.isArray(countries) && countries.length ? 'list' : 'value', 'unknown current country must remain editable instead of falling back to DB/default');
    await first.load('MT7986_1_2');
    assert.equal(first.keylist.filter(x => x === 'DB').length, 1, 'repeat load must not duplicate DB');
    assert.equal(first.validate('MT7986_1_2', 'DB'), true);
    assert.equal(first.validate('MT7986_1_2', 'CN'), true);
    assert.equal(first.validate('MT7986_1_2', ''), true);
    assert.notEqual(first.validate('MT7986_1_2', 'db'), true);
    assert.notEqual(first.validate('MT7986_1_2', 'DBD'), true);
    first.write('MT7986_1_2', 'DB');
    assert.deepEqual(writes, [['MT7986_1_2', 'country', 'DB']]);
    assert.equal(values.arbitrary_radio_5g, 'US', 'selecting first radio must not write second radio');
    second.write('arbitrary_radio_5g', 'DB');
    assert.deepEqual(writes[1], ['arbitrary_radio_5g', 'country', 'DB']);
    assert.equal(await first.load('MT7986_1_2'), 'DB', 'persisted DB reload remains selected');
    assert.equal(first.renderWidget('MT7986_1_2', 0, 'DB'), 'list');
  }
  for (const countries of [standard, []]) {
    const ordinary = option(false, countries, 'radio0', { radio0: 'US' });
    writes.length = 0;
    assert.equal(await ordinary.load('radio0'), 'US');
    assert.equal(ordinary.keylist.includes('DB'), false, 'mac80211 must not gain vendor DB option');
    assert.deepEqual(writes, []);
  }
  assert(loads.includes('MT7986_1_2') && loads.includes('arbitrary_radio_5g'));
  console.log('country behavior passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
