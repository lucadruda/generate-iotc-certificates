#!/usr/bin/env node
import { prompt, registerPrompt } from "inquirer";
import FileTreeSelectionPrompt from "inquirer-file-tree-selection-prompt";
import path from "path";
import { green } from "chalk";
import {
  Certificate,
  generateRoot,
  getCertificateFromPem,
  getPrivateKeyFromPem,
  verify,
} from "./certificate";

async function main(verificationCode?: string) {
  console.log(
    `Welcome to Azure IoT Central Self-signed certificates generator`
  );
  registerPrompt("file-tree-selection", FileTreeSelectionPrompt);
  let rootCA: Certificate;
  let outFolder: string = process.cwd();
  const dir = await prompt([
    {
      type: "file-tree-selection",
      message: "Choose where to save generated certificates",
      name: "parent",
      loop: false,
      onlyShowDir: true,
    },
    {
      type: "input",
      message:
        "Input output folder name. Leave empty if don't want to create a new folder.",
      name: "folder",
      default: null,
    },
  ]);
  outFolder = dir.folder
    ? path.join(dir.parent, dir.folder)
    : path.resolve(dir.parent);

  if (verificationCode) {
    const rootCAFiles = await prompt([
      {
        type: "file-tree-selection",
        message: "Select a signing certificate.",
        name: "certFile",
        onlyShowDir: false,
      },
      {
        type: "file-tree-selection",
        message: "Select a corresponding private key.",
        name: "privKey",
        onlyShowDir: false,
      },
    ]);

    rootCA = await getCertificateFromPem(rootCAFiles.certFile);
    rootCA.privateKey = await getPrivateKeyFromPem(rootCAFiles.privKey);
  } else {
    const transformer = (input: any, answers: any) => {
      if (input.value) {
        return input.value;
      }
      return input;
    };
    const certificateAttrs = await prompt([
      {
        type: "input",
        message: "Insert a Common Name (CN)",
        name: "commonName",
        default: "AzureIoTCentral",
        filter: (input) => {
          return { name: "commonName", value: input };
        },
        transformer,
      },
      {
        type: "input",
        message: "Insert a 2-letters country name",
        name: "countryName",
        default: "US",
        filter: (input) => {
          return { name: "countryName", value: input };
        },
        transformer,
      },
      {
        type: "input",
        message: "Insert a state name",
        name: "stateName",
        default: "Washington",
        filter: (input) => {
          return { shortName: "ST", value: input };
        },
        transformer,
      },
      {
        type: "input",
        message: "Insert a locality name",
        name: "localityName",
        default: "Redmond",
        filter: (input) => {
          return { name: "localityName", value: input };
        },
        transformer,
      },
      {
        type: "input",
        message: "Insert an organization name",
        name: "organizationName",
        default: "Azure",
        filter: (input) => {
          return { name: "organizationName", value: input };
        },
        transformer,
      },
      {
        type: "input",
        message: "Insert an organization unit name",
        name: "OU",
        default: "Azure IoT Central",
        filter: (input) => {
          return { shortName: "OU", value: input };
        },
        transformer,
      },
    ]);

    const generationOptions = await prompt([
      {
        type: "input",
        message: "Insert a passphrase to encrypt private key or leave empty",
        name: "passphrase",
        default: null,
        filter: (input, anwers) => {
          if (!input) {
            return undefined;
          }
          return input;
        },
        transformer: (input) => {
          if (!input) {
            return "";
          }
        },
      },
      {
        type: "list",
        message: "Select key length",
        name: "keyBits",
        default: 0,
        choices: [4096, 2048, 1024],
      },
    ]);

    const options = {
      outFolder,
      ...generationOptions,
      attrs: Object.values(certificateAttrs),
    };

    rootCA = await generateRoot(options);
    console.log(
      green(
        `Successfully generated certificate and private key at '${path.resolve(
          outFolder
        )}`
      )
    );

    //   const leafCount = await prompt([
    //     {
    //       type: "number",
    //       message: "How many leaf certificates would you like to create?",
    //       default: 0,
    //     }]);
    //     if(leafCount>0){
    //         await prompt([
    //             {
    //               type: "",
    //               message: 'Insert device name, in case of multiple devices, this is used as a prefix to generate a unique name (e.g. device => device1,device2):\t"',
    //               default: 0,
    //             }]);
    //     }

    //   ,
    //   ]);

    verificationCode = (
      await prompt([
        {
          message:
            "Upload generated certificate to IoT Central application and insert verification code.",
          name: "verification",
          type: "input",
        },
      ])
    ).verification;
  }

  if (verificationCode) {
    const verified = await verify(
      {
        outFolder,
      },
      verificationCode,
      rootCA
    );
  }
  console.log(green(`Verification certificate created at '${outFolder}'`));
  process.exit(0);
}

const myArgs = process.argv.slice(2);
main(myArgs.length > 0 ? myArgs[0] : undefined);
