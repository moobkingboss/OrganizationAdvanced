// deploy/deploy.ts
import fs from "fs";
import path from "path";
import readline from "readline";
import { ethers as hardhatEthers } from "hardhat";
import { Wallet, JsonRpcProvider } from "ethers";

async function ask(prompt: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise<string>((resolve) =>
    rl.question(prompt, (ans) => {
      rl.close();
      resolve(ans.trim());
    })
  );
}

async function main() {
  const privateKey = await ask("Enter the deployer private key (testnet only): ");
  let rpc = await ask("Enter the RPC URL (press Enter to use public Sepolia: https://sepolia.drpc.org): ");
  if (!rpc) rpc = "https://sepolia.drpc.org";

  const provider = new JsonRpcProvider(rpc);
  const wallet = new Wallet(privateKey, provider);

  console.log("Deployer account:", wallet.address);

  // Deploy the plain UniversalAdapter contract
  const UniversalAdapterFactory = await hardhatEthers.getContractFactory("UniversalAdapter", wallet);
  const factory = await UniversalAdapterFactory.deploy();
  await factory.waitForDeployment();

  const deployedAddress = (factory as any).target || (factory as any).address;
  console.log("UniversalAdapter contract deployed at:", deployedAddress);

  // Write config for the frontend
  const frontendConfigDir = path.join(__dirname, "..", "frontend", "web", "src");
  if (!fs.existsSync(frontendConfigDir)) {
    console.warn("Frontend src directory not found, skipping config.json write:", frontendConfigDir);
  } else {
    const config = {
      network: rpc,
      contractAddress: deployedAddress,
      deployer: wallet.address,
    };
    fs.writeFileSync(
      path.join(frontendConfigDir, "config.json"),
      JSON.stringify(config, null, 2)
    );
    console.log("Wrote frontend config: frontend/web/src/config.json");

    // Copy ABI to the frontend
    try {
      const artifactPath = path.join(
        __dirname,
        "..",
        "artifacts",
        "contracts",
        "UniversalAdapter.sol",
        "UniversalAdapter.json"
      );
      const targetAbiPath = path.join(frontendConfigDir, "abi");
      if (!fs.existsSync(targetAbiPath)) fs.mkdirSync(targetAbiPath, { recursive: true });
      fs.copyFileSync(artifactPath, path.join(targetAbiPath, "UniversalAdapter.json"));
      console.log("Copied ABI to frontend/web/src/abi/UniversalAdapter.json");
    } catch (e) {
      console.warn(
        "Failed to copy ABI automatically. Please copy artifacts/.../UniversalAdapter.json manually to frontend/web/src/abi/UniversalAdapter.json",
        e
      );
    }
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
