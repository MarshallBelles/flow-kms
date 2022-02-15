/* eslint-disable camelcase */
/* eslint-disable indent */
import { KeyManagementServiceClient } from '@google-cloud/kms/build/src/v1';
import { Account, Block } from '@marshallbelles/flow-rest';
import { FlowTs, Config, API } from '../lib';

describe('ContractTesting', () => {
  let flow: FlowTs;

  beforeEach(async () => {
    const MockKMS = new KeyManagementServiceClient();
    Object.assign(MockKMS, {
      cryptoKeyVersionPath: jest.fn((project_id, locationId, keyRingId, keyId, versionId) => {
        return `projects/${project_id}/locations/${locationId}/keyRings/${keyRingId}/cryptoKeys/${keyId}/cryptoKeyVersions/${versionId}`;
      }),
      asymmetricSign: jest.fn((obj: any) => {
        // sign the digest
      }),
    });
    const conf: Config = {
      api: API.LOCALHOST,
      project_id: 'r3volution-us-1',
      locationId: 'us-east1',
      keyId: 'NewTestKey',
      keyRingId: 'r3v-dev',
      versionId: '1',
    };
    flow = new FlowTs(conf, 'credentials.json');
  });

  it('get_account should work', async () => {
    const account = await flow.getAccount('f8d6e0586b0a20c7');
    expect(account instanceof Error).toBeFalsy();
    expect((<Account>account).address).toBe('f8d6e0586b0a20c7');
  });

  it('get_block should work', async () => {
    const block = await flow.getBlock();
    expect(block instanceof Error).toBeFalsy();
    expect((<Block[]>block)[0].height).toBeTruthy();
  });

  it('create_account should work', async () => {
  });

  it('add_contract should work', async () => {
  });

  it('execute_transaction should work', async () => {
  });

  it('send_transaction should work', async () => {
  });

  it('get_transaction_result should work', async () => {
  });

  it('update_contract should work', async () => {
  });

  it('specific authorizers should work', async () => {
  });

  it('remove_contract should work', async () => {
  });

  it('add_key should work', async () => {
  });

  it('remove_key should work', async () => {
  });
});
