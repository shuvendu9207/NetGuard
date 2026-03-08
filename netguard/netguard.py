#!/usr/bin/env python3
"""
NetGuard - Entry Point
Usage:
  python netguard.py run   --pcap input.pcap [--output out.pcap]
  python netguard.py run   --interface eth0
  python netguard.py train --dataset data/captures.csv
"""

from core.dependency_manager import ensure_dependencies
ensure_dependencies()

import argparse
import queue
import time

from capture.capture       import CaptureThread
from parser.packet_parser  import PacketParser
from inspector.sni_extractor import extract_sni, sni_to_app
from inspector.http_inspector import extract_host
from extractor.feature_extractor import FeatureExtractor
from behavior.behavioral_engine  import BehavioralEngine
from rules.rule_engine           import RuleEngine
from alerts.alert_manager        import AlertManager
from reporter.reporter           import Reporter


def run(args):
    print()
    print("=" * 60)
    print("   NetGuard - DPI + ML Intrusion Detection")
    print("=" * 60)

    pkt_queue   = queue.Queue(maxsize=10000)
    behavioral  = BehavioralEngine()
    rules       = RuleEngine()
    alerts      = AlertManager()
    reporter    = Reporter()
    extractor   = FeatureExtractor()

    # Apply CLI blocking rules on top of rules.yaml
    for ip  in (args.block_ip     or []): rules._rules.setdefault("block_ips",     []).append(ip)
    for dom in (args.block_domain or []): rules._rules.setdefault("block_domains", []).append(dom)
    for app in (args.block_app    or []): rules._rules.setdefault("block_apps",    []).append(app)

    # Start capture thread
    capture = CaptureThread(
        packet_queue=pkt_queue,
        pcap_file=args.pcap if hasattr(args, "pcap") else None,
        interface=args.interface if hasattr(args, "interface") else None,
    )
    capture.start()

    # Output PCAP writer
    out_file = None
    if hasattr(args, "output") and args.output:
        import struct
        out_file = open(args.output, "wb")
        # Write PCAP global header
        out_file.write(struct.pack("<IHHiIII",
            0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

    print(f"[*] Reading: {args.pcap if hasattr(args,'pcap') and args.pcap else args.interface}")
    print("[*] Rules loaded | Workers: main thread")
    print()

    processed = 0
    forwarded = 0
    dropped   = 0
    start     = time.time()

    while True:
        try:
            raw = pkt_queue.get(timeout=2)
        except queue.Empty:
            if not capture.is_alive():
                break
            continue

        pkt = PacketParser.parse(raw.data, raw.timestamp)
        if not pkt or not pkt.src_ip:
            continue

        # SNI / HTTP extraction
        sni      = ""
        app_type = "UNKNOWN"
        if pkt.has_tcp and pkt.payload_size > 5:
            if pkt.dst_port == 443:
                sni = extract_sni(pkt.payload) or ""
                if sni:
                    app_type = sni_to_app(sni)
            elif pkt.dst_port == 80:
                host = extract_host(pkt.payload)
                if host:
                    sni = host
                    app_type = "HTTP"

        # Behavioral update
        behavioral.update(pkt.src_ip, pkt.dst_ip,
                          pkt.dst_port, pkt.ip_length, pkt.tcp_flags)
        beh_state = behavioral.get_state(pkt.src_ip)

        # Feature extraction
        features = FeatureExtractor.extract(pkt, sni=sni,
                                            is_http=(app_type=="HTTP"),
                                            behavioral=beh_state)

        # Rule check
        block_reason = rules.is_blocked(
            src_ip=pkt.src_ip,
            dst_port=pkt.dst_port,
            protocol="TCP" if pkt.has_tcp else "UDP" if pkt.has_udp else "ICMP",
            sni=sni,
            app_type=app_type,
        )

        # Behavioral check
        beh_result = behavioral.evaluate(pkt.src_ip)
        if beh_result and not block_reason:
            attack_type, severity = beh_result
            block_reason = f"BEHAVIORAL:{attack_type}"
            alerts.fire(severity=severity, attack_type=attack_type,
                        src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
                        dst_port=pkt.dst_port,
                        protocol="TCP" if pkt.has_tcp else "UDP",
                        detection_method="BEHAVIORAL",
                        sni=sni or None)

        blocked = block_reason is not None
        if blocked:
            dropped += 1
            label = block_reason
        else:
            forwarded += 1
            label = "NORMAL"
            if out_file:
                import struct
                ts_sec  = int(raw.timestamp)
                ts_usec = int((raw.timestamp - ts_sec) * 1_000_000)
                out_file.write(struct.pack("<IIII",
                    ts_sec, ts_usec, len(raw.data), raw.orig_len))
                out_file.write(raw.data)

        # Live console line
        proto = "TCP" if pkt.has_tcp else "UDP" if pkt.has_udp else "ICMP" if pkt.has_icmp else "???"
        sni_str = f"  SNI={sni}" if sni else ""
        status  = f"[91mBLOCKED ({block_reason})[0m" if blocked else "[92mOK[0m"
        print(f"  {proto:<4} {pkt.src_ip}:{pkt.src_port} -> "
              f"{pkt.dst_ip}:{pkt.dst_port}{sni_str}  [{app_type}]  {status}")

        reporter.record(pkt.src_ip, pkt.ip_length, app_type, label, blocked)
        processed += 1

    # Wrap up
    if out_file:
        out_file.close()

    elapsed = time.time() - start
    print()
    reporter.print_summary()
    print(f"  Time elapsed : {elapsed:.2f}s")
    print(f"  Packets read : {capture.total_read}")

    if hasattr(args, "report") and args.report:
        reporter.save_html()


def train(args):
    from ml.trainer import train as do_train
    do_train(dataset_path=args.dataset,
             algorithm=args.algorithm,
             output_path=args.output_model)


def main():
    parser = argparse.ArgumentParser(prog="netguard",
                                     description="NetGuard DPI + ML IDS")
    sub = parser.add_subparsers(dest="command")

    # run
    rp = sub.add_parser("run", help="Start packet analysis")
    rp.add_argument("--pcap",           help="Input PCAP file")
    rp.add_argument("--interface",      help="Live capture interface")
    rp.add_argument("--output",         help="Output filtered PCAP")
    rp.add_argument("--model",          default="ml/models/model.pkl")
    rp.add_argument("--workers",        type=int, default=4)
    rp.add_argument("--export-dataset", action="store_true")
    rp.add_argument("--report",         action="store_true")
    rp.add_argument("--block-app",      action="append", default=[], dest="block_app")
    rp.add_argument("--block-domain",   action="append", default=[], dest="block_domain")
    rp.add_argument("--block-ip",       action="append", default=[], dest="block_ip")

    # train
    tp = sub.add_parser("train", help="Train ML model")
    tp.add_argument("--dataset",      required=True)
    tp.add_argument("--algorithm",    default="random_forest",
                    choices=["random_forest","xgboost","isolation_forest",
                             "one_class_svm","logistic_regression"])
    tp.add_argument("--output-model", default="ml/models/model.pkl",
                    dest="output_model")

    # reload-rules
    sub.add_parser("reload-rules", help="Hot-reload rules.yaml")

    args = parser.parse_args()

    if args.command == "run":
        run(args)
    elif args.command == "train":
        train(args)
    elif args.command == "reload-rules":
        r = RuleEngine()
        r.reload()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
