import { KeyManagementServiceClient } from '@google-cloud/kms';
import { google } from '@google-cloud/kms/build/protos/protos';
import { Account, API, Block, FlowRestClient, Transaction, TransactionResult } from '@marshallbelles/flow-rest';
import * as crypto from 'crypto';
import * as ke from 'key-encoder';

export { Account, API, Block };

export interface Config {
  api: API;
  project_id: string;
  locationId: string;
  keyRingId: string;
  keyId: string;
  versionId: string;
  svcAccount: string;
  keyIndex: string;
}

export enum Digest {
  // eslint-disable-next-line no-unused-vars
  sha256,
  // eslint-disable-next-line no-unused-vars
  sha3_256
}

const argParse = (arg: any): Object => {
  switch (typeof arg) {
    case 'string':
      // handle string
      return {
        type: 'String',
        value: arg,
      };
    case 'boolean':
      // handle boolean
      return {
        type: 'Bool',
        value: arg,
      };
    case 'bigint':
      // handle bigint
      return {
        type: 'Int64',
        value: arg.toString(),
      };
    case 'number':
      // handle number
      if (Number.isInteger(arg)) {
        return {
          type: 'Int',
          value: arg.toString(),
        };
      } else {
        return {
          type: 'Fix64',
          value: arg.toString(),
        };
      }

    default:
      // argument is not supported, convert to string
      return {
        type: 'String',
        value: arg.toString(),
      };
  }
};

const scriptBuilder = (script: string): string => Buffer.from(script, 'utf-8').toString('base64');

const argBuilder = (args: any[]): string[] => {
  const bufs: Array<Buffer> = [];
  args.forEach((a) => {
    // handle map<any, any>
    if (a instanceof Map) {
      const mapEntries: any[] = [];
      a.forEach((v, k) => {
        mapEntries.push({
          key: argParse(k),
          value: argParse(v),
        });
      });
      bufs.push(Buffer.from(JSON.stringify({
        type: 'Dictionary',
        value: mapEntries,
      }), 'utf-8'));
      // assume its string : string
    } else if (Array.isArray(a)) {
      const arrEntries: any[] = [];
      a.forEach((e) => {
        arrEntries.push(argParse(e));
      });
      bufs.push(Buffer.from(JSON.stringify({
        type: 'Array',
        value: arrEntries,
      }), 'utf-8'));
      // handle array
    } else {
      bufs.push(Buffer.from(JSON.stringify(argParse(a))));
    }
  });
  return bufs.map((x) => x.toString('base64'));
};

export class FlowTs {
  private KMSClient: KeyManagementServiceClient;
  private versionName: string;
  private config: Config;
  private RESTClient: FlowRestClient;

  constructor(config: Config, credentialsFile: string, KMSClientOverride?: KeyManagementServiceClient) {
    this.config = config;
    this.KMSClient = KMSClientOverride ? KMSClientOverride : new KeyManagementServiceClient({ credentials_file: credentialsFile });
    this.versionName = this.KMSClient.cryptoKeyVersionPath(this.config.project_id, this.config.locationId, this.config.keyRingId, this.config.keyId, this.config.versionId);
    this.RESTClient = new FlowRestClient(config.api);
  }
  private async getPublicKey(): Promise<google.cloud.kms.v1.IPublicKey> {
    const [publicKey] = await this.KMSClient.getPublicKey({
      name: this.versionName,
    });

    // Optional, but recommended: perform integrity verification on publicKey.
    // For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
    // https://cloud.google.com/kms/docs/data-integrity-guidelines
    const crc32c = require('fast-crc32c');
    if (publicKey.name !== this.versionName) {
      throw new Error('GetPublicKey: request corrupted in-transit');
    }
    if (crc32c.calculate(publicKey.pem) !== Number(publicKey.pemCrc32c?.value)) {
      throw new Error('GetPublicKey: response corrupted in-transit');
    }

    console.log(`Public key pem: ${publicKey.pem}`);

    return publicKey;
  }
  private async signMessage(msg: Buffer): Promise<Buffer> {
    // Create a digest of the message. The digest needs to match the digest
    // configured for the Cloud KMS key.

    // This library only supports KMS: Elliptic Curve P-256 - SHA256 Digest at this time

    const hash = crypto.createHash('sha256');

    hash.update(msg);
    const digest = hash.digest();

    // Optional but recommended: Compute digest's CRC32C.
    const crc32c = require('fast-crc32c');
    const digestCrc32c = crc32c.calculate(digest);

    // Sign the message with Cloud KMS
    const [signResponse] = await this.KMSClient.asymmetricSign({
      name: this.versionName,
      digest: {
        sha256: digest,
      },
      digestCrc32c: {
        value: digestCrc32c,
      },
    });

    if (!signResponse.signature) return Promise.reject(Error('Signature was not returned from KMS'));

    return Buffer.from(signResponse.signature);
  }
  public async getAccount(account: string): Promise<Account | Error> {
    return await this.RESTClient.getAccount(account);
  }
  public async getBlock(id?: string, height?: number): Promise<Block[] | Error> {
    if (id) {
      // get by id
      return await this.RESTClient.getBlock(id);
    } else if (height) {
      // get by height
      return await this.RESTClient.getBlockHeight([height]);
    } else {
      // get latest
      return await this.RESTClient.getLatestBlock();
    }
  }
  public async createAccount(publicKeys?: Array<string>): Promise<Account | Error> {
    const createAccountTemplate = `
      transaction(publicKeys: [String]) {
          prepare(signer: AuthAccount) {
              let acct = AuthAccount(payer: signer)
              for key in publicKeys {
                  acct.addPublicKey(key.decodeHex())
              }
          }
      }`;
    if (!publicKeys) {
      publicKeys = [];
    }
    const svcAccount = await this.RESTClient.getAccount(this.config.svcAccount);
    if (svcAccount instanceof Error) return svcAccount;
    const seqNo = svcAccount.keys.find((k) => k.index == this.config.keyIndex)?.sequence_number;
    if (!seqNo) return Error(`Could not obtain sequence number for key at index: ${this.config.keyIndex}`);
    const proposalKey = {
      address: this.config.svcAccount,
      key_index: this.config.keyIndex,
      sequence_number: seqNo,
    };
    const block = await this.RESTClient.getLatestBlock();
    if (block instanceof Error) return block;
    if (block.length == 0) return Error('Could not retrieve latest block');
    const tx: Transaction = {
      script: scriptBuilder(createAccountTemplate),
      arguments: argBuilder([publicKeys]),
      reference_block_id: block[0].id,
      gas_limit: '9999',
      proposal_key: proposalKey,
      payer: this.config.svcAccount,
      authorizers: [this.config.svcAccount],
      payload_signatures: [],
      envelope_signatures: [],
    };
    const txres = await this.RESTClient.submitTransaction(tx);
    if (txres instanceof Error) return txres;
    // poll for completion
    let resolve: TransactionResult | undefined;
    let backoff = 200;
    while (!resolve) {
      await new Promise<void>((p) => setTimeout(() => p(), backoff));
      backoff += 200;
      const tr = await this.RESTClient.getTransactionResult(txres.id);
      if (tr instanceof Error) return tr;
      switch (tr.status) {
        case 'UNKNOWN':
          break;
        case 'PENDING':
          break;
        case 'FINALIZED':
          break;
        case 'EXECUTED':
          break;
        case 'SEALED':
          resolve = tr;
          break;
        case 'EXPIRED':
          return Error('Transaction Expired!');

        default:
          break;
      }
    }
    // get the new account
    const evt = resolve.events.find((x) => x.type === 'flow.AccountCreated');
    const payload = JSON.parse(Buffer.from(evt?.payload!, 'base64').toString('utf-8'));
    const acctAddress = payload.value.fields[0].value.value.replace(/\b0x/g, '');
    const acct = await this.RESTClient.getAccount(acctAddress);
    return acct;
  }
}
