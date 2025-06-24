#!/usr/bin/env node

import * as Test from './vcp/test/AppTest';
import { Command } from 'commander';

const program = new Command();
program
  .version('1.0.0')
  .description('VCP test runner')
  .option('-r, --revealed'                             , 'run testRevealed')
  .option('-e, --equalities'                           , 'run testEqualities')
  .option('-a, --accumulators'                         , 'run testAccumulators')
  .option('-p, --predicates'                           , 'run testRange (aka predicates)')
  .option('-v, --verifiable-encryption'                , 'run testVerifiableEncryption')
  .option('-v, --verifiable-encryption-dnc-non-blinded', 'run testVerifiableEncryptionDNCNonBlinded')
  .option('-v, --verifiable-encryption-dnc-blinded'    , 'run testVerifiableEncryptionDNCBlinded')
  .action((options) => {
    if (options.revealed)                          { Test.testRevealed(); }
    if (options.equalities)                        { Test.testEqualities(); }
    if (options.accumulators)                      { Test.testAccumulators(); }
    if (options.predicates)                        { Test.testRange(); }
    if (options.verifiableEncryption)              { Test.testVerifiableEncryption(); }
    if (options.verifiableEncryptionDncNonBlinded) { Test.testVerifiableEncryptionDNCNonBlinded(); }
    if (options.verifiableEncryptionDncBlinded)    { Test.testVerifiableEncryptionDNCBlinded(); }
    if (
      !options.revealed &&
      !options.equalities &&
      !options.accumulators &&
      !options.predicates &&
      !options.verifiableEncryption &&
      !options.verifiableEncryptionDncNonBlinded &&
      !options.verifiableEncryptionDncBlinded
    ) {
      Test.testRevealed();
      Test.testEqualities();
      Test.testAccumulators();
      Test.testRange();
      Test.testVerifiableEncryption();
    }
  });

program.parse(process.argv);
