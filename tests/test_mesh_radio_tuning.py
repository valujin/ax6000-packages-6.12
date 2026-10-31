"""Real-UCI bounded MU-MIMO adoption and rollback overlay validation."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from test_mesh_network_materialize import UCI
from test_mesh_slot_allocation import LIB, NATIVE

class RadioTuning(unittest.TestCase):
 def setUp(self):
  self.assertTrue((LIB/'ax6000-mesh-radio-tuning').exists())
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  for n in ['base','current','state','bin','uci-delta']:(self.root/n).mkdir()
  (self.root/'bin/uci').symlink_to(UCI)
  sha=self.root/'bin/sha256sum';sha.write_text('#!/bin/sh\nexec busybox sha256sum "$@"\n');sha.chmod(0o700)
  wireless=''
  for band,device in [('2g','radio0'),('5g','radio1')]:
   wireless+=f"config wifi-device '{device}'\n option type 'mtwifi'\n option band '{band}'\nconfig wifi-iface 'main_{device}'\n option device '{device}'\n option mode 'ap'\n option ssid 'fixture'\n option key 'private-key'\n"
  (self.root/'state/original-wireless').write_text(wireless)
  for device in ['radio0','radio1']:wireless+=f"config wifi-iface 'ax6000_mesh_{device}'\n option mode 'ap'\n option device '{device}'\n option mumimo_dl '0'\n option mumimo_ul '0'\n"
  for directory in ['base','current']:
   (self.root/directory/'wireless').write_text(wireless)
   for n in ['dat0','dat1']:(self.root/directory/n).write_text('BssidNum=2\nMuMimoDlEnable=0;0\nMuMimoUlEnable=0;0\nCountryCode=GB\n')
  board=self.root/'board'; board.write_text('xiaomi,mi-router-ax3000t\n')
  profile=self.root/'l1profile'; profile.write_text('INDEX0=MT7981\nINDEX0_profile_path=/etc/wireless/mediatek/mt7981.dbdc.b0.dat;/etc/wireless/mediatek/mt7981.dbdc.b1.dat\n')
  hardware=(LIB/'ax6000-mesh-hardware').read_text().replace('/tmp/sysinfo/board_name',str(board)).replace('/etc/wireless/l1profile.dat',str(profile))
  hardware=hardware.replace("printf '/etc/wireless/mediatek/%s.dbdc.b0.dat\\n' \"$prefix\"", "printf '%s\\n' '"+str(self.root/'current/dat0')+"'")
  hardware=hardware.replace("printf '/etc/wireless/mediatek/%s.dbdc.b1.dat\\n' \"$prefix\"", "printf '%s\\n' '"+str(self.root/'current/dat1')+"'")
  self.hardware=self.root/'hardware'; self.hardware.write_text(hardware); self.hardware.chmod(0o755)
  source=(LIB/'ax6000-mesh-radio-tuning').read_text().replace('/etc/config/wireless',str(self.root/'current/wireless')).replace('/etc/ax6000-mesh',str(self.root/'state')).replace('/etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat',str(self.root/'current/dat0')).replace('/etc/wireless/mediatek/mt7986-ax6000.dbdc.b1.dat',str(self.root/'current/dat1'))
  source=source.replace('/usr/libexec/ax6000-mesh-hardware',str(self.hardware))
  self.helper=self.root/'helper';self.helper.write_text(source)
  self.env={**os.environ,'PATH':str(self.root/'bin')+':'+os.environ['PATH'],'LD_LIBRARY_PATH':str(NATIVE/'lib')}
 def change(self,section,option,value):
  subprocess.run([UCI,'-c',str(self.root/'current'),'-t',str(self.root/'uci-delta'),'set',f'wireless.{section}.{option}={value}'],env=self.env,check=True,capture_output=True)
  subprocess.run([UCI,'-c',str(self.root/'current'),'-t',str(self.root/'uci-delta'),'commit','wireless'],env=self.env,check=True,capture_output=True)
 def call(self,ok=True):
  r=subprocess.run(['busybox','ash',str(self.helper),str(self.root/'base'),str(self.root/'out')],env=self.env,capture_output=True,text=True)
  self.assertEqual(r.returncode==0,ok,r.stderr);self.assertNotIn('private-key',r.stdout+r.stderr)
 def enable(self):
  for d in ['radio0','radio1']:
   for opt in ['mumimo_dl','mumimo_ul']:self.change('main_'+d,opt,'1')
  for n in ['dat0','dat1']:
   p=self.root/'current'/n;p.write_text(p.read_text().replace('=0;0','=1;0'))
 def test_valid_mu_change_preserves_options_without_mesh_sections_in_rollback(self):
  self.enable();self.call();s=(self.root/'out/rollback-wireless').read_text();self.assertNotIn('ax6000_mesh_',s);self.assertEqual(s.count("option mumimo_dl '1'"),2);self.assertEqual(s.count("option mumimo_ul '1'"),2)
 def test_credential_change_rejected(self):self.enable();self.change('main_radio0','key','different-key');self.call(False)
 def test_mesh_owned_option_change_rejected(self):self.enable();self.change('ax6000_mesh_radio0','mumimo_dl','1');self.call(False)
 def test_nonboolean_rejected(self):self.enable();self.change('main_radio0','mumimo_dl','2');self.call(False)
 def test_changed_file_modes_rejected(self):
  self.enable();(self.root/'current/wireless').chmod(0o777);self.call(False)
 def test_symlink_current_radio_file_rejected(self):
  self.enable();p=self.root/'current/dat0';saved=self.root/'saved-dat';p.rename(saved);p.symlink_to(saved);self.call(False)
 def test_unrelated_dat_change_rejected(self):
  self.enable();p=self.root/'current/dat0';p.write_text(p.read_text()+'Unowned=1\n');self.call(False)
 def test_dat_token_order_must_match_uci(self):
  self.enable();p=self.root/'current/dat0';p.write_text(p.read_text().replace('=1;0','=0;1'));self.call(False)
 def test_existing_native_wsc_and_channel_exceptions_remain_supported(self):
  self.enable();p=self.root/'current/dat0';p.write_text(p.read_text()+'SSID1=native-update\nWPAPSK2=native-key\nChannel=36\n');self.call()
 def test_duplicate_dat_key_rejected(self):
  self.enable();p=self.root/'current/dat0';p.write_text(p.read_text()+'MuMimoDlEnable=1;0\n');self.call(False)

class RadioTuningTransaction(RadioTuning):
 def setUp(self):
  super().setUp()
  import re,hashlib
  state=self.root/'state';self.original_wireless=(state/'original-wireless').read_bytes()
  self.transaction=self.root/'transaction'
  text=(LIB/'ax6000-mesh-transaction').read_text()
  replacements={'/etc/ax6000-mesh':str(state),'/etc/config/wireless':str(self.root/'current/wireless'),'/etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat':str(self.root/'current/dat0'),'/etc/wireless/mediatek/mt7986-ax6000.dbdc.b1.dat':str(self.root/'current/dat1'),'/usr/libexec/ax6000-mesh-radio-tuning':str(self.helper),'/var/lock':str(self.root/'locks')}
  replacements['/usr/libexec/ax6000-mesh-hardware']=str(self.hardware)
  for a,b in replacements.items():text=text.replace(a,b)
  text=text.replace('/etc/',str(self.root/'etc')+'/')
  text=text.replace(' = 0:700 ]',' = '+str(os.getuid())+':700 ]')
  text=re.sub(r'(\$\(stat -c %u [^\n]+?\)" = )0( \])',r'\g<1>'+str(os.getuid())+r'\2',text)
  self.transaction.write_text(text)
  self.helper.chmod(0o700)
  (self.root/'locks').mkdir();(self.root/'etc/config').mkdir(parents=True);(self.root/'etc/init.d').mkdir()
  (self.root/'etc/config/ax6000_mesh').write_text("config mesh 'main'\n option enabled '1'\n option role 'controller'\n option backhaul 'wireless'\n")
  # UCI live lookup uses this package directory while explicit -c operations
  # continue to use the real UCI parser for before/after/rollback candidates.
  (self.root/'bin/uci').unlink();(self.root/'bin/uci').write_text('#!/bin/sh\nexec '+UCI+' -c "'+str(self.root/'etc/config')+'" -t "'+str(self.root/'uci-delta')+'" "$@"\n');(self.root/'bin/uci').chmod(0o700)
  for package in ['wireless','network','dhcp']:
   if package=='wireless':(self.root/'etc/config/wireless').symlink_to(self.root/'current/wireless')
   else:(self.root/'etc/config'/package).write_text('')
  watchdog=self.root/'etc/init.d/ax6000-mesh-watchdog';watchdog.write_text('#!/bin/sh\nexit 0\n');watchdog.chmod(0o700)
  paths=text.split("cat <<PATHS\n",1)[1].split('\nPATHS',1)[0].replace('$dat0',str(self.root/'current/dat0')).replace('$dat1',str(self.root/'current/dat1'))
  for line in paths.splitlines():
   label,path=line.split(' ',1);p=Path(path)
   if p.exists():
    original=state/('original-'+label)
    if label!='wireless':original.write_bytes(p.read_bytes())
    original.chmod(p.stat().st_mode&0o777);(state/('mode-'+label)).write_text(f'{os.getuid()}:{os.getgid()}:{p.stat().st_mode&0o777:o}')
   else:(state/('absent-'+label)).touch()
  for n,v in [('role','controller'),('backhaul','wireless'),('phase','pending'),('was-running-dnsmasq','0'),('was-running-odhcpd','0')]: (state/n).write_text(v+'\n')
  (state/'snapshot.sha256').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in state.iterdir() if p.name!='phase'))
  self.tx('seal');self.tx('commit')
 def tx(self,*args,ok=True):
  r=subprocess.run(['busybox','ash',str(self.transaction),*args],env=self.env,capture_output=True,text=True)
  self.assertEqual(r.returncode==0,ok,r.stderr);return r
 def test_adoption_updates_check_and_preserves_original(self):
  self.enable();self.tx('adopt-radio-tuning');self.tx('check')
  state=self.root/'state';self.assertEqual((state/'original-wireless').read_bytes(),self.original_wireless)
  baseline=state/(state/'radio-baseline-path').read_text().strip();s=(baseline/'rollback-wireless').read_text();self.assertNotIn('ax6000_mesh_',s);self.assertEqual(s.count("option mumimo_dl '1'"),2)
 def test_authenticated_legacy_import_and_adoption(self):
  state=self.root/'state';(state/'radio-baseline-path').unlink();(self.root/'base').chmod(0o700)
  self.enable();self.tx('import-radio-baseline',str(self.root/'base'));self.tx('adopt-radio-tuning');self.tx('check')
 def test_legacy_current_rebase_is_refused(self):
  state=self.root/'state';(state/'radio-baseline-path').unlink();(self.root/'current').chmod(0o700)
  self.enable();self.tx('import-radio-baseline',str(self.root/'current'),ok=False);self.assertFalse((state/'radio-baseline-path').exists())
 def test_unchanged_legacy_restart_needs_no_import(self):
  (self.root/'state/radio-baseline-path').unlink();self.tx('adopt-radio-tuning');self.assertTrue((self.root/'state/radio-baseline-path').exists())
 def test_legacy_canonical_agent_wts_does_not_rebase_or_block_restart(self):
  import hashlib
  state=self.root/'state';(state/'role').write_text('agent\n')
  manifest=state/'snapshot.sha256';lines=manifest.read_text().splitlines();manifest.write_text('\n'.join(hashlib.sha256((state/'role').read_bytes()).hexdigest()+'  role' if l.endswith('  role') else l for l in lines)+'\n')
  mesh=self.root/'etc/config/ax6000_mesh';mesh.write_text(mesh.read_text().replace("'controller'","'agent'"))
  wts=self.root/'etc/map/wts_bss_info_config';wts.parent.mkdir();wts.write_text('original accepted WTS\n');wts.chmod(0o600)
  (state/'phase').write_text('pending\n');(state/'expected').unlink();self.tx('seal');self.tx('commit')
  (state/'backhaul-ssid').write_text('FixtureBH\n');(state/'backhaul-key').write_text('fixture-backhaul-key\n')
  vendor=LIB.parent/'share/ax6000-mesh/vendor.sh'
  subprocess.run(['busybox','ash','-c','. "$1"; mesh_write_bss "$2" AX6000-joining fixture-backhaul-key sae-mixed AX6000-joining fixture-backhaul-key sae-mixed FixtureBH fixture-backhaul-key','fixture',str(vendor),str(wts)],check=True,capture_output=True)
  (self.root/'run').mkdir();text=self.transaction.read_text().replace('/usr/share/ax6000-mesh/vendor.sh',str(vendor)).replace('/var/run/',str(self.root/'run')+'/');self.transaction.write_text(text)
  (state/'radio-baseline-path').unlink();before=(state/'expected').read_bytes();self.tx('check');self.tx('adopt-radio-tuning')
  self.assertEqual((state/'expected').read_bytes(),before);self.assertFalse((state/'radio-baseline-path').exists())
 def test_mode_only_edit_is_not_adopted(self):
  (self.root/'current/wireless').chmod(0o777);self.tx('adopt-radio-tuning',ok=False)
 def test_mode_and_mu_edit_are_not_adopted(self):
  self.enable();(self.root/'current/dat0').chmod(0o777);self.tx('adopt-radio-tuning',ok=False)
 def test_unrelated_mesh_change_refuses_adoption(self):
  self.enable();p=self.root/'etc/config/ax6000_mesh';p.write_text(p.read_text()+" option other '1'\n");self.tx('adopt-radio-tuning',ok=False)
 def test_startup_check_recovers_published_radio_journal(self):
  self.enable();self.tx('adopt-radio-tuning');state=self.root/'state';name=(state/'radio-baseline-path').read_text();baseline=state/name.strip()
  (state/'expected').write_bytes((baseline/'before-expected').read_bytes());(state/'radio-tuning-pending').write_text(name)
  self.tx('check');self.assertFalse((state/'radio-tuning-pending').exists());self.assertEqual((state/'expected').read_bytes(),(baseline/'expected').read_bytes())
 def test_disable_restores_user_mu_without_mesh_sections(self):
  self.enable();self.tx('adopt-radio-tuning')
  for service in ['dnsmasq','odhcpd']:
   p=self.root/'etc/init.d'/service;p.write_text('#!/bin/sh\nexit 0\n');p.chmod(0o700)
  p=self.root/'bin/pidof';p.write_text('#!/bin/sh\nexit 1\n');p.chmod(0o700)
  self.tx('rollback','boot')
  s=(self.root/'current/wireless').read_text();self.assertNotIn('ax6000_mesh_',s);self.assertEqual(s.count("option mumimo_dl '1'"),2);self.assertEqual(s.count("option mumimo_ul '1'"),2)
 def test_callback_validates_before_stop_and_restarts_mu_change(self):
  self.enable();self.callback(True)
 def test_callback_bad_edit_does_not_stop_native_service(self):
  self.enable();self.change('main_radio0','key','different-key');self.callback(False)
 def callback(self,ok):
  text=(LIB/'ax6000-mesh-radio-ready').read_text().replace('/var/run',str(self.root/'run')).replace('/var/lock',str(self.root/'locks')).replace('/usr/libexec/ax6000-mesh-transaction',str(self.transaction)).replace('/etc/init.d/ax6000-mesh',str(self.root/'service'))
  self.transaction.chmod(0o700);(self.root/'run').mkdir();p=self.root/'bin/sleep';p.write_text('#!/bin/sh\nexit 0\n');p.chmod(0o700)
  p=self.root/'callback';p.write_text(text)
  service=self.root/'service';service.write_text('#!/bin/sh\necho STOP >> "'+str(self.root/'events')+'"\n"'+str(self.transaction)+'" check || exit 1\necho START >> "'+str(self.root/'events')+'"\n');service.chmod(0o700)
  r=subprocess.run(['sh',str(p)],env=self.env,capture_output=True,text=True)
  self.assertEqual(r.returncode==0,ok,r.stderr)
  if ok:self.assertEqual((self.root/'events').read_text(),'STOP\nSTART\n')
  else:self.assertFalse((self.root/'events').exists())
 def test_changed_live_file_blocks_journal_replay(self):
  self.enable();self.tx('adopt-radio-tuning');state=self.root/'state';name=(state/'radio-baseline-path').read_text();baseline=state/name.strip()
  (state/'expected').write_bytes((baseline/'before-expected').read_bytes());(state/'radio-tuning-pending').write_text(name)
  self.change('main_radio0','key','different-key');self.tx('check',ok=False);self.assertTrue((state/'radio-tuning-pending').exists())
