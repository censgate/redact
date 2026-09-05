#!/usr/bin/env python3
"""
Export HuggingFace NER models to ONNX format for use with redact-ner.

Usage:
    python export_ner_model.py --model dslim/bert-base-NER --output models/

Requirements:
    pip install transformers torch onnx optimum[exporters]
"""

import argparse
import json
import shutil
from pathlib import Path

def export_model(model_name: str, output_dir: str, quantize: bool = False):
    """Export a HuggingFace NER model to ONNX format."""
    try:
        from transformers import AutoTokenizer, AutoModelForTokenClassification
        from optimum.onnxruntime import ORTModelForTokenClassification
        import torch
    except ImportError as e:
        print(f"Error: Missing required package - {e}")
        print("Install with: pip install transformers torch optimum[exporters]")
        return False

    print(f"📦 Loading model: {model_name}")
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    try:
        # Load model and tokenizer
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForTokenClassification.from_pretrained(model_name)

        print(f"✓ Model loaded successfully")
        print(f"  - Model parameters: {sum(p.numel() for p in model.parameters()):,}")
        print(f"  - Labels: {len(model.config.id2label)}")

        # Export to ONNX
        print(f"\n🔄 Exporting to ONNX...")
        ort_model = ORTModelForTokenClassification.from_pretrained(
            model_name,
            export=True,
        )

        # Save ONNX model
        onnx_path = output_path / "model.onnx"
        ort_model.save_pretrained(output_path)

        # Copy ONNX model file
        for file in output_path.glob("*.onnx"):
            if file.name != "model.onnx":
                file.rename(output_path / "model.onnx")

        # Save tokenizer
        print(f"💾 Saving tokenizer...")
        tokenizer.save_pretrained(output_path)

        # Create label mapping configuration
        print(f"📝 Creating label mapping...")
        config = {
            "model_path": str(onnx_path),
            "tokenizer_path": str(output_path / "tokenizer.json"),
            "min_confidence": 0.7,
            "max_seq_length": 512,
            "id2label": model.config.id2label,
            "label_mappings": create_label_mappings(model.config.id2label),
        }

        config_path = output_path / "config.json"
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

        print(f"\n✅ Export complete!")
        print(f"  - Model: {onnx_path}")
        print(f"  - Tokenizer: {output_path / 'tokenizer.json'}")
        print(f"  - Config: {config_path}")

        if quantize:
            print("\n🔢 Dynamic INT8 quantization (onnxruntime.quantization)")
            print("   Can move logits across the 0.7 confidence floor.")
            print("   Do not ship without a CoNLL PER/ORG/LOC F1 floor vs FP32.")
            try:
                from onnxruntime.quantization import QuantType, quantize_dynamic
            except ImportError as qe:
                print(f"❌ onnxruntime is required for --quantize: {qe}")
                print("Install with: pip install onnxruntime")
                return False
            quantized_path = output_path / "model.int8.onnx"
            quantize_dynamic(
                model_input=str(onnx_path),
                model_output=str(quantized_path),
                weight_type=QuantType.QInt8,
            )
            onnx_path.unlink()
            quantized_path.rename(onnx_path)
            print(f"  - Wrote quantized {onnx_path}")

        # Display size
        model_size = onnx_path.stat().st_size / (1024 * 1024)
        print(f"  - Model size: {model_size:.1f} MB")
        if quantize:
            print("  - Quantization: dynamic INT8 (ungated — validate F1 before shipping)")

        print(f"\n🧪 Test with:")
        print(f"  cargo test --package redact-ner --test ner_e2e -- --ignored")

        return True

    except Exception as e:
        print(f"❌ Error during export: {e}")
        import traceback
        traceback.print_exc()
        return False

def create_label_mappings(id2label: dict) -> dict:
    """Create EntityType mappings from model labels."""
    mappings = {}

    for label_id, label in id2label.items():
        if label == "O" or not label:
            continue

        # Remove B-/I- prefix for mapping
        entity_type = label.split("-")[1] if "-" in label else label

        # Map to standard entity types
        if entity_type in ["PER", "PERSON"]:
            mappings[label] = "Person"
        elif entity_type in ["ORG", "ORGANIZATION"]:
            mappings[label] = "Organization"
        elif entity_type in ["LOC", "LOCATION", "GPE"]:
            mappings[label] = "Location"
        elif entity_type in ["DATE", "TIME", "DATETIME"]:
            mappings[label] = "DateTime"
        elif entity_type == "MISC":
            print(f"  ℹ️  MISC label detected: {label} - may need custom mapping")

    return mappings

def main():
    parser = argparse.ArgumentParser(
        description="Export HuggingFace NER models to ONNX format"
    )
    parser.add_argument(
        "--model",
        type=str,
        required=True,
        help="HuggingFace model name (e.g., dslim/bert-base-NER)",
    )
    parser.add_argument(
        "--output",
        type=str,
        required=True,
        help="Output directory for ONNX model",
    )
    parser.add_argument(
        "--quantize",
        action="store_true",
        help="Dynamic INT8 quantization (experimental; requires a CoNLL F1 floor before shipping)",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("  NER Model Export Tool")
    print("=" * 60)
    print()

    success = export_model(args.model, args.output, args.quantize)

    if success:
        print("\n✅ Export successful!")
        return 0
    else:
        print("\n❌ Export failed!")
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())
