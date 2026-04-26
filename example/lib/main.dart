// Reference app for the flutter_wireguard plugin.
//
// Demonstrates every feature exposed by the plugin:
//   - keypair generation
//   - start/stop a tunnel from a wg-quick config
//   - status snapshots + live status stream
//   - tunnelNames(), backend()
//   - persisting saved tunnels via SharedPreferences
import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_wireguard/flutter_wireguard.dart' as wg;
import 'package:shared_preferences/shared_preferences.dart';

void main() => runApp(const ExampleApp());

class ExampleApp extends StatelessWidget {
  const ExampleApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'flutter_wireguard example',
        theme: ThemeData(useMaterial3: true, colorSchemeSeed: Colors.indigo),
        home: const HomePage(),
      );
}

class SavedTunnel {
  SavedTunnel({required this.name, required this.config});
  final String name;
  final String config;

  Map<String, String> toJson() => {'name': name, 'config': config};
  static SavedTunnel fromJson(Map<String, dynamic> j) =>
      SavedTunnel(name: j['name'] as String, config: j['config'] as String);
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});
  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  static const _prefsKey = 'saved_tunnels_v1';

  final _nameCtl = TextEditingController(text: 'wg0');
  final _configCtl = TextEditingController();
  final List<SavedTunnel> _saved = [];
  wg.BackendInfo? _backend;
  wg.TunnelStatus? _lastStatus;
  StreamSubscription<wg.TunnelStatus>? _sub;
  String _log = '';

  @override
  void initState() {
    super.initState();
    _loadSaved();
    _refreshBackend();
    _sub = wg.statusStream().listen((s) {
      setState(() => _lastStatus = s);
    });
  }

  @override
  void dispose() {
    _sub?.cancel();
    _nameCtl.dispose();
    _configCtl.dispose();
    super.dispose();
  }

  Future<void> _refreshBackend() async {
    try {
      final b = await wg.backend();
      setState(() => _backend = b);
    } catch (e) {
      _appendLog('backend(): $e');
    }
  }

  Future<void> _loadSaved() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getStringList(_prefsKey) ?? const <String>[];
    setState(() {
      _saved
        ..clear()
        ..addAll(raw.map((s) => SavedTunnel.fromJson(jsonDecode(s) as Map<String, dynamic>)));
    });
  }

  Future<void> _persistSaved() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setStringList(
        _prefsKey, _saved.map((s) => jsonEncode(s.toJson())).toList());
  }

  void _appendLog(String s) {
    debugPrint(s);
    setState(() => _log = '${DateTime.now().toIso8601String()}  $s\n$_log');
  }

  Future<void> _generateKeyPair() async {
    final pair = await wg.generateKeyPair();
    _appendLog('Generated keypair: public=${pair.publicKey}');
    if (!mounted) return;
    showDialog<void>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('New WireGuard keypair'),
        content: SelectableText(
            'Private key:\n${pair.privateKey}\n\nPublic key:\n${pair.publicKey}'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Close')),
        ],
      ),
    );
  }

  Future<void> _start() async {
    try {
      await wg.start(_nameCtl.text.trim(), _configCtl.text);
      _appendLog('start(${_nameCtl.text}) OK');
    } catch (e) {
      _appendLog('start failed: $e');
    }
  }

  Future<void> _stop() async {
    try {
      await wg.stop(_nameCtl.text.trim());
      _appendLog('stop(${_nameCtl.text}) OK');
    } catch (e) {
      _appendLog('stop failed: $e');
    }
  }

  Future<void> _status() async {
    try {
      final s = await wg.status(_nameCtl.text.trim());
      setState(() => _lastStatus = s);
      _appendLog(
          'status: ${s.name} ${s.state.name} rx=${s.rx} tx=${s.tx} hs=${s.handshake}');
    } catch (e) {
      _appendLog('status failed: $e');
    }
  }

  Future<void> _tunnelNames() async {
    try {
      final names = await wg.tunnelNames();
      _appendLog('tunnelNames: $names');
    } catch (e) {
      _appendLog('tunnelNames failed: $e');
    }
  }

  Future<void> _saveCurrent() async {
    final name = _nameCtl.text.trim();
    if (name.isEmpty) return;
    setState(() {
      _saved.removeWhere((s) => s.name == name);
      _saved.add(SavedTunnel(name: name, config: _configCtl.text));
    });
    await _persistSaved();
  }

  Future<void> _loadInto(SavedTunnel s) async {
    setState(() {
      _nameCtl.text = s.name;
      _configCtl.text = s.config;
    });
  }

  Future<void> _deleteSaved(SavedTunnel s) async {
    setState(() => _saved.removeWhere((x) => x.name == s.name));
    await _persistSaved();
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(
          title: const Text('flutter_wireguard example'),
          actions: [
            IconButton(
                onPressed: _refreshBackend,
                tooltip: 'Refresh backend',
                icon: const Icon(Icons.refresh)),
          ],
        ),
        body: SingleChildScrollView(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _BackendBanner(backend: _backend),
              const SizedBox(height: 16),
              _StatusCard(status: _lastStatus),
              const SizedBox(height: 16),
              TextField(
                controller: _nameCtl,
                decoration: const InputDecoration(
                    labelText: 'Tunnel name', border: OutlineInputBorder()),
              ),
              const SizedBox(height: 8),
              TextField(
                controller: _configCtl,
                minLines: 6,
                maxLines: 14,
                style: const TextStyle(fontFamily: 'monospace'),
                decoration: const InputDecoration(
                    labelText: 'wg-quick config',
                    hintText: '[Interface]\nPrivateKey = ...\n...',
                    border: OutlineInputBorder()),
              ),
              const SizedBox(height: 12),
              Wrap(spacing: 8, runSpacing: 8, children: [
                FilledButton.icon(
                    onPressed: _start,
                    icon: const Icon(Icons.play_arrow),
                    label: const Text('Start')),
                FilledButton.tonalIcon(
                    onPressed: _stop,
                    icon: const Icon(Icons.stop),
                    label: const Text('Stop')),
                OutlinedButton.icon(
                    onPressed: _status,
                    icon: const Icon(Icons.info_outline),
                    label: const Text('Status')),
                OutlinedButton.icon(
                    onPressed: _tunnelNames,
                    icon: const Icon(Icons.list),
                    label: const Text('Tunnel names')),
                OutlinedButton.icon(
                    onPressed: _generateKeyPair,
                    icon: const Icon(Icons.vpn_key),
                    label: const Text('Generate keypair')),
                OutlinedButton.icon(
                    onPressed: _saveCurrent,
                    icon: const Icon(Icons.save),
                    label: const Text('Save')),
              ]),
              const SizedBox(height: 24),
              if (_saved.isNotEmpty) ...[
                const Text('Saved tunnels',
                    style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600)),
                const SizedBox(height: 8),
                ..._saved.map((s) => Card(
                      child: ListTile(
                        title: Text(s.name),
                        subtitle: Text(
                          s.config.split('\n').take(2).join(' / '),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                        onTap: () => _loadInto(s),
                        trailing: IconButton(
                          icon: const Icon(Icons.delete_outline),
                          onPressed: () => _deleteSaved(s),
                        ),
                      ),
                    )),
                const SizedBox(height: 24),
              ],
              const Text('Log',
                  style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600)),
              const SizedBox(height: 8),
              Container(
                padding: const EdgeInsets.all(12),
                color: Colors.black87,
                child: SelectableText(
                  _log.isEmpty ? '(empty)' : _log,
                  style: const TextStyle(
                      fontFamily: 'monospace', color: Colors.greenAccent),
                ),
              ),
            ],
          ),
        ),
      );
}

class _BackendBanner extends StatelessWidget {
  const _BackendBanner({required this.backend});
  final wg.BackendInfo? backend;

  @override
  Widget build(BuildContext context) {
    final b = backend;
    final label = b == null ? 'Detecting backend…' : '${b.kind.name} — ${b.detail}';
    final color = b == null
        ? Colors.grey
        : b.kind == wg.BackendKind.unknown
            ? Colors.red
            : (b.kind == wg.BackendKind.kernel ? Colors.green : Colors.amber);
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: color.withOpacity(0.15),
        border: Border.all(color: color),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(children: [
        Icon(Icons.electrical_services, color: color),
        const SizedBox(width: 8),
        Expanded(child: Text(label, style: const TextStyle(fontWeight: FontWeight.w500))),
      ]),
    );
  }
}

class _StatusCard extends StatelessWidget {
  const _StatusCard({required this.status});
  final wg.TunnelStatus? status;

  @override
  Widget build(BuildContext context) {
    final s = status;
    if (s == null) {
      return const Card(
        child: Padding(
          padding: EdgeInsets.all(16),
          child: Text('No status yet — start a tunnel or query Status.'),
        ),
      );
    }
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('${s.name}  •  ${s.state.name.toUpperCase()}',
                style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            Text('rx: ${s.rx} bytes'),
            Text('tx: ${s.tx} bytes'),
            Text('handshake: ${s.handshake == 0 ? "never" : DateTime.fromMillisecondsSinceEpoch(s.handshake)}'),
          ],
        ),
      ),
    );
  }
}
