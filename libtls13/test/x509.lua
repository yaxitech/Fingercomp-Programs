local match = require("luassert.match")

local base64 = require("tls13.base64")
local util = require("tls13.util")

context("X.509 certificate parser tests #x509", function()
  local asn = require("tls13.asn")
  local x509 = require("tls13.x509")

  local function loadPemFile(path)
    local certs = {}
    local certLines = nil
    local caName

    for line in io.lines(path) do
      line = line:gsub("\r", "")

      if certLines then
        if line:sub(1, 5) == "-----" then
          table.insert(certs, {
            caName,
            assert(base64.decode(table.concat(certLines)))
          })
          certLines = nil
        else
          table.insert(certLines, line)
        end
      elseif line:sub(1, 1) == "#" then
        caName = line:sub(3)
      elseif line:sub(1, 5) == "-----" then
        certLines = {}
      end
    end

    return certs
  end

  context("CA certificates", function()
    local certs = loadPemFile("test/data/ca-bundle.pem")

    for _, cert in ipairs(certs) do
      local caName, cert = table.unpack(cert)

      test("CA " .. caName, function()
        local decode = spy.new(asn.decode)
        local certAsn = decode(cert)
        assert.spy(decode).returned.with(match.is.table())

        local parse = spy.new(x509.parseCertificateFromAsn)
        local result = parse(certAsn)
        assert.spy(parse).returned.with(match.is.table())
      end)
    end
  end)

  test("RSASSA-PSS signature certificate", function()
    local oid = require("tls13.asn.oid")

    local cert = loadPemFile("test/data/rsassa-pss.pem")[1][2]
    local decode = spy.new(asn.decode)
    local certAsn = decode(cert)
    assert.spy(decode).returned.with(match.is.table())

    local parse = spy.new(x509.parseCertificateFromAsn)
    local result = parse(certAsn)
    assert.spy(parse).returned.with(match.is.table())

    assert:set_parameter("TableFormatLevel", -1)
    assert.is_not.nil_(result.tbsCertificate)
    assert.is_not.nil_(result.tbsCertificate.signature)
    assert.same({
      algorithm = oid.pkcs1.rsassaPss,
      parameters = {
        hashAlgorithm = {
          algorithm = oid.hashalgs.sha512,
          parameters = false,
        },
        maskGenAlgorithm = {
          algorithm = oid.pkcs1.mgf1,
          parameters = {
            algorithm = oid.hashalgs.sha512,
            parameters = false,
          },
        },
        saltLength = 64,
        trailerField = 1,
      },
    }, result.tbsCertificate.signature)
  end)

  test("AMD SEV certificate", function()
    local extOid = asn.makeOid(1, 3, 6, 1, 4, 1, 3704, 1, 4)
    local recognizedExtensions = require("tls13.x509.ext").recognizedExtensions

    local cert = loadPemFile("test/data/amd-sev.pem")[1][2]
    local decode = spy.new(asn.decode)
    local certAsn = decode(cert)
    assert.spy(decode).returned.with(match.is.table())

    local parse = spy.new(x509.parseCertificateFromAsn)

    recognizedExtensions[extOid] = {
      getName = function()
        return "AMD VCEK hwID"
      end,

      parse = function(_, _, value)
        return value
      end,

      nonDerEncodedValue = true,
    }

    local success, result = xpcall(parse, debug.traceback, certAsn)
    recognizedExtensions[extOid] = nil
    assert(success, result)

    assert.spy(parse).returned.with(match.is.table())

    local exts = result.tbsCertificate.extensions
    local ext = exts[extOid]

    assert.same(
      "9dc99962c063029e430b6f7b734075ec542f4f3ec639e657e14585d3fe559b38532bc42\z
        d037d618317694ad6634d2507964e276c8eedeac4978c7006bf89f8e1",
      util.toHex(ext.extnValue)
    )
  end)

  context("VCEK Chain Genoa", function()
    local oid = require("tls13.asn.oid")
    local bitstring = require("tls13.asn.bitstring")
    local utilMap = require("tls13.util.map")

    local chain = loadPemFile("test/data/vcek-chain-genoa.pem")

    for _, element in ipairs(chain) do
      local name, certDer = table.unpack(element)
      local certAsn = asn.decode(certDer)
      local cert, err = x509.parseCertificateFromAsn(certAsn)

      assert:set_parameter("TableFormatLevel", -1)
      assert.is_not.nil_(cert.tbsCertificate)

      if name == "SEV-VCEK" then
        test("AMD " .. name, function()
          assert.same({
            tbsCertificate = {
              version = 3,
              serialNumber = util.fromHex("0000000000000000"),
              issuer = {
                {
                  { type = oid.at.organizationalUnitName, value = "Engineering" },
                },
                {
                  { type = oid.at.countryName, value = "US" },
                },
                {
                  { type = oid.at.localityName, value = "Santa Clara" },
                },
                {
                  { type = oid.at.stateOrProvinceName, value = "CA" },
                },
                {
                  { type = oid.at.organizationName, value = "Advanced Micro Devices" },
                },
                {
                  { type = oid.at.commonName, value = "SEV-Genoa" },
                },
              },
              signature = {
                algorithm = oid.pkcs1.rsassaPss,
                parameters = {
                  hashAlgorithm = {
                    algorithm = oid.hashalgs.sha384,
                    parameters = false,
                  },
                  maskGenAlgorithm = {
                    algorithm = oid.pkcs1.mgf1,
                    parameters = {
                      algorithm = oid.hashalgs.sha384,
                      parameters = false,
                    },
                  },
                  saltLength = 48,
                  trailerField = 1,
                },
              },
              validity = {
                notBefore = {
                  year = 2025,
                  month = 7,
                  day = 20,
                  hour = 22,
                  minute = 15,
                  second = 42,
                },
                notAfter = {
                  year = 2032,
                  month = 7,
                  day = 20,
                  hour = 22,
                  minute = 15,
                  second = 42,
                },
              },
              subject = {
                {
                  { type = oid.at.organizationalUnitName, value = "Engineering" },
                },
                {
                  { type = oid.at.countryName, value = "US" },
                },
                {
                  { type = oid.at.localityName, value = "Santa Clara" },
                },
                {
                  { type = oid.at.stateOrProvinceName, value = "CA" },
                },
                {
                  { type = oid.at.organizationName, value = "Advanced Micro Devices" },
                },
                {
                  { type = oid.at.commonName, value = "SEV-VCEK" },
                },
              },
              subjectPublicKeyInfo = {
                algorithm = {
                  algorithm = oid.ansiX962.keyType.ecPublicKey,
                  parameters = {
                    namedCurve = oid.iso.identifiedOrganization.certicom.curve.ansip384r1,
                  },
                },
                subjectPublicKey = bitstring.fromHex(
                  "044AB0A6F9F085E7512A1E5A14AA1521C86CB0E3049F2CAF908B2DDE0610CB8C8" ..
                  "53CA94EE398D4F0D10E6F464EAA884F105A80C0892C8DDFC4FA12AF1C9131A7A9" ..
                  "91A42B95819BC3BDAFBBC7E7AA769CA2DCFB0B89F60CD6FF237886F3903E45BB"
                ),
              },
              extensions = utilMap.makeProjectionMap(tostring, {
                [oid.amdSnp.structVersion] = {
                  extnID = oid.amdSnp.structVersion,
                  critical = false,
                  extnValue = 0,
                },
                [oid.amdSnp.productName] = {
                  extnID = oid.amdSnp.productName,
                  critical = false,
                  extnValue = "Genoa",
                },
                [oid.amdSnp.tcbVersion.blSPL] = {
                  extnID = oid.amdSnp.tcbVersion.blSPL,
                  critical = false,
                  extnValue = 9,
                },
                [oid.amdSnp.tcbVersion.teeSPL] = {
                  extnID = oid.amdSnp.tcbVersion.teeSPL,
                  critical = false,
                  extnValue = 0,
                },
                [oid.amdSnp.tcbVersion.spl_4] = {
                  extnID = oid.amdSnp.tcbVersion.spl_4,
                  critical = false,
                  extnValue = 0,
                },
                [oid.amdSnp.tcbVersion.spl_5] = {
                  extnID = oid.amdSnp.tcbVersion.spl_5,
                  critical = false,
                  extnValue = 0,
                },
                [oid.amdSnp.tcbVersion.spl_6] = {
                  extnID = oid.amdSnp.tcbVersion.spl_6,
                  critical = false,
                  extnValue = 0,
                },
                [oid.amdSnp.tcbVersion.spl_7] = {
                  extnID = oid.amdSnp.tcbVersion.spl_7,
                  critical = false,
                  extnValue = 0,
                },
                [oid.amdSnp.tcbVersion.snpSPL] = {
                  extnID = oid.amdSnp.tcbVersion.snpSPL,
                  critical = false,
                  extnValue = 23,
                },
                [oid.amdSnp.tcbVersion.ucodeSPL] = {
                  extnID = oid.amdSnp.tcbVersion.ucodeSPL,
                  critical = false,
                  extnValue = 72,
                },
                [oid.amdSnp.hwID] = {
                  extnID = oid.amdSnp.hwID,
                  critical = false,
                  extnValue = util.fromHex(
                    "9dc99962c063029e430b6f7b734075ec542f4f3ec639e657e14585d3fe559b38" ..
                    "532bc42d037d618317694ad6634d2507964e276c8eedeac4978c7006bf89f8e1"
                  ),
                },
              }),
            },
            signatureAlgorithm = {
              algorithm = oid.pkcs1.rsassaPss,
              parameters = {
                hashAlgorithm = {
                  algorithm = oid.hashalgs.sha384,
                  parameters = false,
                },
                maskGenAlgorithm = {
                  algorithm = oid.pkcs1.mgf1,
                  parameters = {
                    algorithm = oid.hashalgs.sha384,
                    parameters = false,
                  },
                },
                saltLength = 48,
                trailerField = 1,
              },
            },
            signatureValue = bitstring.fromHex(
              "58c555e0d3e6995186ab221741c37b4c7142e661065ba1243cedc634f5f749e2" ..
              "0f89c72493d8a267da8239f2f3f5fbbca8c96c46cc53cb5f212a3aa54b744bbd" ..
              "f577d5fa6145835929af12d16582fec0df2b4c91246da2da0ddb173c5a22da5b" ..
              "5dd94c817de162acb29557a9a4286ec2605d950ec216b6d9fe5aeedcaf6fe047" ..
              "ab960b826c49fc806b6c188b7cd22346513d35ee075a6bae60e6c3e79d148294" ..
              "7c6ea55b7c603d0b949f32c3e99c2338c0a2f980f716a902b8d443fca20aa95b" ..
              "43c8992156646dc88b6e37af9c89003b6612f943a687797c6514e6845c5ac777" ..
              "f1619ac6a9bf349c9d76be6607a1aca04d8afd0274d8374eb17a5f213b6d5161" ..
              "ef7bd540e4a89c4c40f1e0ba5abaa3d5283710947cd1c9ed1cbce927d265dbc6" ..
              "822c5e30557adc988697f3bdac0881cf3becf9f5f27094d2257d5768ca387032" ..
              "84d88df0ad62133c0af1916e7511263f787bec638840e095accf08c2bfb4a144" ..
              "5ccc9675e7b82116451ee4eba9e8f84f2f171e05113a327062dcdf505915c10b" ..
              "9f3d7e4d5b518aee348f9ba3eb5016bc94e0192a366f1c6159f4f90064dd79a3" ..
              "7312d045decda18083412983a9416b3eee02708db474ec470fd1a46d8095d22d" ..
              "ccbe473b32fa96b3a17cfa8c2ad169e1de32573d9119e7c3f2c28ee40c88da1c" ..
              "f87001d2d1e7a594819808aa3c46be682029a9910578b1e3ffe5da9ef008a933"
            ),
          }, cert)
        end)
      end
    end
  end)

  test("Let's Encrypt certificate", function()
    local bitstring = require("tls13.asn.bitstring")
    local oid = require("tls13.asn.oid")
    local utilMap = require("tls13.util.map")

    local cert = loadPemFile("test/data/lencr-org.pem")[1][2]
    local certAsn = asn.decode(cert)

    local parse = spy.new(x509.parseCertificateFromAsn)
    local result = parse(certAsn)
    assert.spy(parse).returned.with(match.is.table())

    assert:set_parameter("TableFormatLevel", -1)
    assert.same({
      tbsCertificate = {
        version = 3,
        serialNumber = util.fromHex("0426e21be0d8cd31cfe4407e0ece8bac9e0b"),

        signature = {
          algorithm = oid.pkcs1.sha256WithRSAEncryption,
          parameters = false,
        },

        issuer = {
          {
            {type = oid.at.countryName, value = "US"},
          },

          {
            {type = oid.at.organizationName, value = "Let's Encrypt"},
          },

          {
            {type = oid.at.commonName, value = "R3"},
          },
        },

        validity = {
          notBefore = {
            year = 2023,
            month = 6,
            day = 1,
            hour = 22,
            minute = 20,
            second = 23,
          },
          notAfter = {
            year = 2023,
            month = 8,
            day = 30,
            hour = 22,
            minute = 20,
            second = 22,
          },
        },

        subject = {
          {
            {type = oid.at.commonName, value = "lencr.org"},
          },
        },

        subjectPublicKeyInfo = {
          algorithm = {
            algorithm = oid.ansiX962.keyType.ecPublicKey,
            parameters = {
              namedCurve = oid.ansiX962.curves.prime.prime256r1,
            },
          },

          subjectPublicKey = bitstring.fromHex(
            "04d5d1be9b1811\z
            4b3fef26731652d9\z
            6bcbff968c60cef6\z
            ccd27d22140cb6cb\z
            bfb51eaf39f4e85f\z
            48d4b729a589985a\z
            0c5f601df2a61ec9\z
            3fb8fa32a3a4b0a2\z
            7811"
          ),
        },

        extensions = utilMap.makeProjectionMap(tostring, {
          [oid.ce.keyUsage] = {
            extnID = oid.ce.keyUsage,
            critical = true,
            extnValue = {
              digitalSignature = true,
              nonRepudiation = false,
              keyEncipherment = false,
              dataEncipherment = false,
              keyAgreement = false,
              keyCertSign = false,
              cRLSign = false,
              encipherOnly = false,
              decipherOnly = false,
            },
          },

          [oid.ce.extKeyUsage] = {
            extnID = oid.ce.extKeyUsage,
            critical = false,
            extnValue = {
              oid.pkix.kp.serverAuth,
              oid.pkix.kp.clientAuth,
            },
          },

          [oid.ce.basicConstraints] = {
            extnID = oid.ce.basicConstraints,
            critical = true,
            extnValue = {cA = false},
          },

          [oid.ce.subjectKeyIdentifier] = {
            extnID = oid.ce.subjectKeyIdentifier,
            critical = false,
            extnValue =
              util.fromHex("0414bbd925908f538bdc0fd09d08492e923b80eadf69"),
          },

          [oid.ce.authorityKeyIdentifier] = {
            extnID = oid.ce.authorityKeyIdentifier,
            critical = false,
            extnValue =
              util.fromHex("30168014142eb317b75856cbae500940e61faf9d8b14c2c6"),
          },

          [oid.pkix.pe.authorityInfoAccess] = {
            extnID = oid.pkix.pe.authorityInfoAccess,
            critical = false,
            extnValue = util.fromHex(
              "3047302106082b060105050730018615\z
              687474703a2f2f72332e6f2e6c656e63\z
              722e6f7267302206082b060105050730\z
              028616687474703a2f2f72332e692e6c\z
              656e63722e6f72672f"
            ),
          },

          [oid.ce.subjectAltName] = {
            extnID = oid.ce.subjectAltName,
            critical = false,
            extnValue = {
              {dNSName = "lencr.org"},
              {dNSName = "letsencrypt.com"},
              {dNSName = "letsencrypt.org"},
              {dNSName = "www.lencr.org"},
              {dNSName = "www.letsencrypt.com"},
              {dNSName = "www.letsencrypt.org"},
            },
          },

          [oid.ce.certificatePolicies] = {
            extnID = oid.ce.certificatePolicies,
            critical = false,
            extnValue = utilMap.makeProjectionMap(tostring, {
              [oid.internet / 4 / 1 / 44947 / 1 / 1 / 1] = {
                policyIdentifier = oid.internet / 4 / 1 / 44947 / 1 / 1 / 1,
                policyQualifiers = {
                  {
                    policyQualifierId = oid.pkix.qt.cps,
                    qualifier = "http://cps.letsencrypt.org",
                  },
                },
              },

              [oid.jointIsoCcitt / 23 / 140 / 1 / 2 / 1] = {
                policyIdentifier = oid.jointIsoCcitt / 23 / 140 / 1 / 2 / 1,
              },
            }),
          },

          [oid.internet / 4 / 1 / 11129 / 2 / 4 / 2] = {
            extnID = oid.internet / 4 / 1 / 11129 / 2 / 4 / 2,
            critical = false,
            extnValue = util.fromHex(
              "0481f100ef007600b73efb24df9c4dba\z
              75f239c5ba58f46c5dfc42cf7a9f35c4\z
              9e1d098125edb49900000188794325b6\z
              0000040300473045022100d23151e270\z
              77742d62d59266766a75940a4126cf22\z
              d5ba36071bac10ef04882702207338b5\z
              47636dd98a2e10b5282858f9322996cf\z
              d8f12e8f369c0453a806cd9fdf007500\z
              7a328c54d8b72db620ea38e0521ee984\z
              16703213854d3bd22bc13a57a352eb52\z
              00000188794325cb0000040300463044\z
              02204e212729a3dadab0108701e6db56\z
              6fbeefb670fd0c48998e1779df0aee5f\z
              1be202200bf43ef12b65f5bc843f5ce4\z
              e009a4abedb5ec1bb65540b62fd57335\z
              1ad4b1ef"
            ),
          },
        }),
      },

      signatureAlgorithm = {
        algorithm = oid.pkcs1.sha256WithRSAEncryption,
        parameters = false,
      },

      signatureValue = bitstring.fromHex(
        "8c3a5eb5c9\z
        42c9b3bb4c72fdc8cbb774229f5cc165\z
        478088fb4f4009bcdfbc72b441c7ed60\z
        eb162acae8a9b1f2aa82ff8474de57b8\z
        f934fa2b71e5e228b328a503aafc7f65\z
        f8356e92c129c253a4ee6d7faf3c4e62\z
        3e76acbc96acecba5ad851156dc4078c\z
        68e39b54f64ccbdf7deffa597f061ded\z
        c6a32140e5b920e64f244886091f0c36\z
        091f35ee51ef5b740b6ddc303c2810cb\z
        816c071e7a951ab8384e7be41e751cf5\z
        d29d9d0579381b88ae3d610990e4a4db\z
        1e5545f2e84da84bb63b5357e165afbd\z
        b6843a56ce51b98e1d0bbee6f858dbaf\z
        50d5bc27182c12547d7371bb9c0fa037\z
        bc91eb650f39a2d35cbcd2595b206fab\z
        0e2413dd38ace8d7f19550"
      ),
    }, result)
  end)
end)
