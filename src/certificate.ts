#!/usr/bin/env node
import { pki, md } from "node-forge";
import * as path from "path";
import { promises as fs } from "fs";
import { createInterface } from "readline";

type InputReader = {
  question: (questionText: string) => Promise<string>;
};

const getInputReader = function (): InputReader {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return {
    question: (questionText: string) => {
      return new Promise((resolve) => {
        rl.question(questionText, (answer) => {
          resolve(answer);
        });
      });
    },
  };
};

export type Certificate = pki.Certificate;
export const AttributeNameLookup = {
  COMMON_NAME: "commonName",
  COUNTRY_NAME: "countryName",
  LOCALITY_NAME: "localityName",
  STATE_NAME: "ST",
  ORGANIZATION_NAME: "organizationName",
  ORGANIZATION_UNIT: "OU",
};
export type AttributeName = keyof typeof AttributeNameLookup;

export type CertificatesOptions = {
  outFolder: string;
  passphrase?: string;
  yearsTTL?: number;
  keyBits?: number;
  attrs?: pki.CertificateField[];
};

let certificateAttrs: pki.CertificateField[];

const certificateExtensions = [
  {
    name: "subjectKeyIdentifier",
  },
  {
    name: "keyUsage",
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true,
  },
  {
    name: "extKeyUsage",
    serverAuth: true,
    clientAuth: true,
    codeSigning: true,
    emailProtection: true,
    timeStamping: true,
  },
  {
    name: "nsCertType",
    client: true,
    server: true,
    email: true,
    objsign: true,
    sslCA: true,
    emailCA: true,
    objCA: true,
  },
];

async function createCAPrivKey(
  options: CertificatesOptions
): Promise<pki.rsa.KeyPair & { encryptedKey?: string }> {
  return new Promise((resolve, reject) => {
    pki.rsa.generateKeyPair(
      {
        bits: options.keyBits ?? 4096,
        algorithm: "AES-256-CBC",
      },
      async (err, keypair) => {
        if (err) {
          return reject(err);
        }
        if (options.passphrase) {
          return resolve({
            encryptedKey: pki.encryptRsaPrivateKey(
              keypair.privateKey,
              options.passphrase
            ),
            ...keypair,
          });
        }
        resolve(keypair);
      }
    );
  });
}

export async function createCert(
  options: CertificatesOptions,
  name?: pki.Certificate
): Promise<pki.Certificate>
export async function createCert(
  options: CertificatesOptions,
  issuer: pki.Certificate,
  name?: string,
): Promise<pki.Certificate>
export async function createCert(
  options: CertificatesOptions,
  issuer?: pki.Certificate,
  name?: string,
): Promise<pki.Certificate> {
  const key = await createCAPrivKey(options);
  const keyTowrite = key.encryptedKey ?? pki.privateKeyToPem(key.privateKey);
  await fs.writeFile(
    path.join(
      options.outFolder,
      `${name
        ? name
        : options.attrs?.find((a) => a.name === "commonName")?.value
      }.key.pem`
    ),
    keyTowrite
  );

  const outcert = pki.createCertificate();
  if (options.attrs) {
    outcert.setSubject(options.attrs);
    outcert.setIssuer(options.attrs);
  }
  outcert.validity.notBefore = new Date();
  outcert.validity.notAfter = new Date();
  outcert.publicKey = key.publicKey;
  outcert.privateKey = pki.privateKeyFromPem(keyTowrite);
  outcert.validity.notAfter.setFullYear(
    outcert.validity.notBefore.getFullYear() + 1
  );
  outcert.serialNumber = `${Math.floor(Math.random() * 1000)}`;
  outcert.setExtensions([
    ...certificateExtensions,
    ...(issuer
      ? []
      : [
        {
          name: "basicConstraints",
          cA: true,
        },
      ]),
  ]);
  if (issuer) {
    outcert.setIssuer(issuer.subject.attributes);
    outcert.sign(issuer.privateKey, md.sha256.create());

    if (!issuer.verify(outcert)) {
      throw "Something went wrong when creating leaf certificate.";
    }
  } else {
    outcert.sign(key.privateKey, md.sha256.create());
  }
  return outcert;
}

export async function generateRoot(
  options: CertificatesOptions
): Promise<pki.Certificate> {
  try {
    await fs.mkdir(options.outFolder, { recursive: true });
    // generate root
    const caCert = await createCert(options);
    await fs.writeFile(
      path.join(
        options.outFolder,
        `${options.attrs?.find((a) => a.name === "commonName")?.value}.cert.pem`
      ),
      pki.certificateToPem(caCert)
    );
    return caCert;
  } catch (e) {
    console.log(e);
    throw e;
  }
}

export async function getCertificateFromPem(pemPath: string) {
  const pem = (await fs.readFile(pemPath)).toString();
  return pki.certificateFromPem(pem);
}

export async function getPrivateKeyFromPem(pemPath: string) {
  const pem = (await fs.readFile(pemPath)).toString();
  return pki.privateKeyFromPem(pem);
}

export async function getLeavesCertificates(options: CertificatesOptions, count: number, prefix: string, rootCA: pki.Certificate): Promise<pki.Certificate[]> {
  const res: pki.Certificate[] = [];
  if (!options.attrs) {
    options.attrs = rootCA.subject.attributes;
  }
  for (let i = 1; i <= count; i++) {
    const name = `${prefix}${count > 1 ? i : ""}`;
    const leafOptions: CertificatesOptions = {
      ...options,
      attrs: options.attrs?.map((a) => {
        if (a.name === "commonName" || a.shortName === "CN") {
          return { name: "commonName", value: name };
        }
        return { ...a };
      })
    };
    const leaf = await createCert(leafOptions, rootCA);
    const outName = path.join(options.outFolder, `${name}.pem`);
    await fs.writeFile(
      outName,
      `${pki.certificateToPem(leaf)}${pki.certificateToPem(rootCA)}`
    );
    res.push(leaf);
  }
  return res;
}
// export async function createDevices(
//   count: number,
//   prefix: string,
//   rootCertificate: pki.Certificate
// ) {
//   for (let i = 1; i <= count; i++) {
//     const name = `${prefix}${count > 1 ? i : ""}`;
//     Log("INFO", `Creating certificates for ${name}`);
//     try {
//       const leaf = await createCert(name, rootCertificate);
//       const outName = path.join(options.outFolder, `${name}.cert.pem`);
//       await fs.writeFile(
//         outName,
//         `${pki.certificateToPem(leaf)}${pki.certificateToPem(rootCertificate)}`
//       );
//     } catch (e) {}
//   }
// }
export async function verify(
  options: CertificatesOptions,
  verificationCode: string,
  rootCA: pki.Certificate
): Promise<pki.Certificate> {
  await fs.mkdir(options.outFolder, { recursive: true });
  if (!options.attrs) {
    options.attrs = rootCA.subject.attributes;
  }
  const verificationOptions: CertificatesOptions = {
    ...options,
    attrs: options.attrs?.map((a) => {
      if (a.name === "commonName" || a.shortName === "CN") {
        return { name: "commonName", value: verificationCode };
      }
      return { ...a };
    }),
  };
  const validated = await createCert(verificationOptions, rootCA,'verification');
  const outName = path.join(options.outFolder, "verified.pem");
  await fs.writeFile(
    outName,
    `${pki.certificateToPem(validated)}${pki.certificateToPem(rootCA)}`
  );
  return validated;
}
