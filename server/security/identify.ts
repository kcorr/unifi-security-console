// Best guess at what a device is when UniFi doesn't say: from its name, the maker behind its MAC address, UniFi's own
// fingerprint and whether it uses a private (randomized) address. Purely local and passive: nothing contacts the device.

import type { DeviceIdentity } from '../../shared/types.ts';

export interface IdentifyInput {
  mac: string;
  name: string | null;
  hostname: string | null;
  /** Maker from UniFi, or from the offline IEEE register. */
  maker: string | null;
  makerSource: 'unifi' | 'registry' | null;
  /** UniFi's fingerprint label ("Linux", "iPhone"…) and how sure it is (0–100). */
  fingerprint: string | null;
  fingerprintConfidence: number | null;
  wired: boolean;
  network: string | null;
}

/** The locally-administered bit: set on randomized "private" Wi-Fi addresses (and some virtual adapters). */
export function isPrivateMac(mac: string): boolean {
  const first = parseInt(mac.replace(/[^0-9a-f]/gi, '').slice(0, 2), 16);
  return Number.isFinite(first) && (first & 0x02) !== 0;
}

// Address blocks that always mean a virtual machine or container.
const VIRTUAL: [prefix: string, what: string][] = [
  ['BC2411', 'a virtual machine or container on Proxmox'],
  ['005056', 'a VMware virtual machine'],
  ['000C29', 'a VMware virtual machine'],
  ['000569', 'a VMware virtual machine'],
  ['00155D', 'a Hyper-V virtual machine'],
  ['080027', 'a VirtualBox virtual machine'],
  ['525400', 'a QEMU/KVM virtual machine'],
  ['00163E', 'a Xen virtual machine'],
  ['0242', 'a Docker container'],
];

// Device names that give the type away (most specific first).
const NAMES: [RegExp, string][] = [
  [/iphone/i, 'an iPhone'],
  [/ipad/i, 'an iPad'],
  [/apple-?tv/i, 'an Apple TV'],
  [/homepod/i, 'a HomePod'],
  [/macbook|imac|mac-?mini|mac-?pro|-mbp\b|-mba\b/i, 'a Mac'],
  [/^(desktop|laptop|win)-[a-z0-9]+$/i, 'a Windows PC (it still has the name Windows gave it)'],
  [/android|galaxy|pixel|oneplus|redmi|xiaomi|moto/i, 'an Android phone or tablet'],
  [/^esp[_-]|esp32|esp8266|tasmota|esphome|shelly|wled|sonoff|tuya|smartlife/i, 'a smart-home gadget (an ESP-based plug, switch, sensor or light)'],
  [/chromecast|google-?home|nest/i, 'a Google Nest or Chromecast device'],
  [/echo|alexa|fire-?tv|kindle|amazon-/i, 'an Amazon Echo, Fire TV or Kindle'],
  [/ring-|^ring$/i, 'a Ring doorbell or camera'],
  [/roku/i, 'a Roku streamer or TV'],
  [/sonos/i, 'a Sonos speaker'],
  [/^hp[0-9a-f]{6}$|^npi[0-9a-f]+|^brw[0-9a-f]+|epson|canon|printer|laserjet|officejet/i, 'a printer'],
  [/raspberrypi|^pi[0-9]*$/i, 'a Raspberry Pi'],
  [/proxmox|^pve|unraid|truenas|synology|^ds[0-9]{3,4}|qnap|-nas\b|^nas/i, 'a server or NAS'],
  [/webos|lgtv|samsung.*tv|bravia|vizio|tcl|hisense/i, 'a smart TV'],
  [/xbox|playstation|^ps[345]\b|nintendo|switch/i, 'a game console'],
  [/vivint|smarthub|simplisafe|adt|alarm/i, 'a home security hub'],
  [/ecobee|thermostat|honeywell/i, 'a thermostat'],
  [/camera|cam\b|reolink|wyze|arlo|eufy|doorbell/i, 'a camera'],
];

// What a maker usually builds, for devices without a telling name.
const MAKERS: [RegExp, string][] = [
  [/espressif/i, 'a smart-home gadget built on an Espressif Wi-Fi chip (smart plug, bulb, switch or sensor)'],
  [/tuya|itead|sonoff|allterco|shelly|lumi united|aqara/i, 'a smart-home gadget'],
  [/amazon/i, 'an Amazon device (Echo, Fire TV, Kindle, Ring or Blink)'],
  [/google/i, 'a Google device (Nest speaker or display, Chromecast or Pixel)'],
  [/apple/i, 'an Apple device (iPhone, iPad, Mac, Apple TV or HomePod)'],
  [/sonos/i, 'a Sonos speaker'],
  [/roku/i, 'a Roku streamer or TV'],
  [/ubiquiti/i, 'a Ubiquiti/UniFi device'],
  [/raspberry/i, 'a Raspberry Pi'],
  [/proxmox|vmware|parallels/i, 'a virtual machine'],
  [/synology|qnap|asustor|western digital|seagate|buffalo/i, 'a NAS or storage device'],
  [/super ?micro|dell|lenovo|asrock|gigabyte|micro-star|asustek|framework/i, 'a computer or server'],
  [/intel corporate|liteon|lite-on|azurewave|hon hai|foxconn|realtek|rivet|killer|qualcomm|mediatek/i, 'a laptop or PC (its Wi-Fi or network card)'],
  [/hewlett|hp inc/i, 'an HP printer or computer'],
  [/brother|canon|seiko epson|lexmark|xerox|kyocera|ricoh/i, 'a printer'],
  [/samsung/i, 'a Samsung phone, tablet, TV or appliance'],
  [/lg electronics|lg innotek|vizio|tcl|hisense|tpv|sharp/i, 'a TV or home appliance'],
  [/nintendo|sony interactive/i, 'a game console'],
  [/microsoft/i, 'a Microsoft device (Xbox or Surface)'],
  [/ecobee|resideo|honeywell|emerson/i, 'a thermostat'],
  [/arlo|wyze|reolink|hikvision|dahua|axis comm|eufy|anker/i, 'a camera'],
  [/signify|philips lighting|lutron|leviton|lifx/i, 'a lighting controller or smart light'],
  [/vivint|simplisafe|alarm\.com|ring llc/i, 'a home security device'],
  [/alpha networks|murata|universal global|gainspan|silicon lab|texas instruments|nordic semi|cypress|broadcom|chongqing|shenzhen|hangzhou/i, 'an appliance or smart-home device with a built-in Wi-Fi module'],
];

const first = <T>(rules: [RegExp, T][], text: string | null) => (text ? rules.find(([re]) => re.test(text))?.[1] ?? null : null);

export function identifyDevice(d: IdentifyInput): DeviceIdentity {
  const clues: string[] = [];
  const hex = d.mac.replace(/[^0-9a-f]/gi, '').toUpperCase();
  const oui = hex.length >= 6 ? `${hex.slice(0, 2)}:${hex.slice(2, 4)}:${hex.slice(4, 6)}` : null;
  const privateAddress = isPrivateMac(d.mac);
  const named = (d.name && d.name.toLowerCase() !== d.mac.toLowerCase()) || !!d.hostname;
  let guess: string | null = null;
  let confidence: DeviceIdentity['confidence'] = null;
  const consider = (g: string | null, c: NonNullable<DeviceIdentity['confidence']>) => {
    const rank = { high: 3, medium: 2, low: 1 } as const;
    if (g && (!confidence || rank[c] > rank[confidence])) {
      guess = g;
      confidence = c;
    }
  };

  const virtual = VIRTUAL.find(([p]) => hex.startsWith(p));
  if (virtual) {
    clues.push(`Its address block (${oui}) is used only for ${virtual[1].replace(/^an? /, '')}s.`);
    consider(virtual[1], 'high');
  }
  for (const text of [d.hostname, d.name]) {
    const byName = first(NAMES, text);
    if (byName) {
      clues.push(`Its name “${text}” looks like ${byName}.`);
      consider(byName, 'high');
      break;
    }
  }
  if (d.maker) {
    clues.push(`Made by ${d.maker}${d.makerSource === 'registry' ? ' (from the IEEE register of MAC addresses)' : ' (according to UniFi)'}.`);
    consider(first(MAKERS, d.maker), 'medium');
  }
  if (d.fingerprint) {
    clues.push(`UniFi's fingerprint says “${d.fingerprint}”${d.fingerprintConfidence !== null ? ` (${d.fingerprintConfidence}% sure)` : ''}.`);
    consider(`a ${d.fingerprint} device`, d.fingerprintConfidence !== null && d.fingerprintConfidence >= 80 ? 'medium' : 'low');
  }
  if (privateAddress && !virtual) {
    clues.push('It uses a private (randomized) Wi-Fi address, so the maker can’t be read from it. Phones, tablets, laptops and watches do this by default.');
    consider('a phone, tablet, laptop or watch', 'low');
  }
  if (!named) clues.push('It has no name in UniFi. You can give it one there, so it is easier to recognise everywhere.');
  if (d.network) clues.push(`It is on the ${d.network} network${d.wired ? ', wired' : ', over Wi-Fi'}.`);

  // Online lookups are links the owner opens: only the maker part of the address (first half) goes in them.
  const lookups: DeviceIdentity['lookups'] = [];
  if (oui && !privateAddress) lookups.push({ label: `Look up ${oui} online`, url: `https://maclookup.app/search/result?mac=${encodeURIComponent(oui)}` });
  const search = [d.maker, d.hostname].filter(Boolean).join(' ');
  if (search) lookups.push({ label: 'Search the web for it', url: `https://duckduckgo.com/?q=${encodeURIComponent(search)}` });

  return { guess, confidence, maker: d.maker, makerSource: d.maker ? d.makerSource : null, privateAddress, clues, lookups };
}
