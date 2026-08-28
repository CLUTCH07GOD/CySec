"""
Upload Fine-Tuned LoRA Adapters to Hugging Face Hub
---------------------------------------------------
This script scans the local `adapters/` directory, filters out
heavy training checkpoints (checkpoint-*/, optimizer.pt, scaler.pt),
and uploads all clean adapter safetensors, configs, and metadata
to a Hugging Face model repository.

Usage:
    python scripts/upload_adapters_to_hf.py --repo-id <YOUR_USERNAME/compliance-qwen-adapters>
"""

import os
import glob
import argparse
from dotenv import load_dotenv
from huggingface_hub import HfApi, create_repo, login

load_dotenv()

ALLOWED_FILES = {
    "adapter_model.safetensors",
    "adapter_config.json",
    "metadata.json",
    "README.md",
    "tokenizer.json",
    "tokenizer_config.json",
    "chat_template.jinja"
}

def main():
    parser = argparse.ArgumentParser(description="Upload trained LoRA adapters to Hugging Face Hub.")
    parser.add_argument(
        "--token",
        type=str,
        default=os.getenv("HF_TOKEN"),
        help="Hugging Face write token (optional if already logged in or in .env)"
    )
    parser.add_argument(
        "--repo-id",
        type=str,
        default=os.getenv("HF_ADAPTERS_REPO", "ClutchGod07/compliance-qwen-adapters"),
        help="Target Hugging Face repository ID (e.g. username/repo-name)"
    )
    parser.add_argument(
        "--adapters-dir",
        type=str,
        default="adapters",
        help="Path to local adapters folder"
    )
    parser.add_argument(
        "--private",
        action="store_true",
        help="Make the Hugging Face repository private"
    )
    args = parser.parse_args()

    # Authenticate
    if args.token:
        login(token=args.token)

    api = HfApi(token=args.token)

    print(f"[*] Ensuring repository exists on Hugging Face: {args.repo_id} (private={args.private})...")
    create_repo(repo_id=args.repo_id, repo_type="model", private=args.private, exist_ok=True, token=args.token)


    adapter_dirs = sorted([
        d for d in glob.glob(f"{args.adapters_dir}/*")
        if os.path.isdir(d) and os.path.exists(os.path.join(d, "adapter_model.safetensors"))
    ])

    if not adapter_dirs:
        print(f"[!] No valid adapter directories found under '{args.adapters_dir}'.")
        return

    print(f"[*] Found {len(adapter_dirs)} trained adapters to upload:\n" + "\n".join(f"  - {os.path.basename(d)}" for d in adapter_dirs))
    print("-" * 60)

    uploaded_count = 0
    for adapter_path in adapter_dirs:
        domain_name = os.path.basename(adapter_path)
        print(f"\n[+] Processing adapter: {domain_name}")

        for root, dirs, files in os.walk(adapter_path):
            # Skip intermediate checkpoints and optimizer states
            if "checkpoint-" in root:
                continue

            for file in files:
                if file in ALLOWED_FILES:
                    local_file_path = os.path.join(root, file)
                    path_in_repo = f"{domain_name}/{file}"
                    file_size_mb = os.path.getsize(local_file_path) / (1024 * 1024)
                    print(f"    --> Uploading {path_in_repo} ({file_size_mb:.2f} MB)...")
                    api.upload_file(
                        path_or_fileobj=local_file_path,
                        path_in_repo=path_in_repo,
                        repo_id=args.repo_id,
                        repo_type="model"
                    )
                    uploaded_count += 1

    print("\n" + "=" * 60)
    print(f"[✓] SUCCESS: Uploaded {uploaded_count} files across {len(adapter_dirs)} adapters to https://huggingface.co/{args.repo_id}")
    print("=" * 60)

if __name__ == "__main__":
    main()
