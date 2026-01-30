
rule Crypto_Constants
{
    strings:
        $md5_1 = { 01 23 45 67 }
        $md5_2 = { 89 AB CD EF }
        $sha1_1 = { 67 45 23 01 }
        $sha1_2 = { EF CD AB 89 }
    condition:
        any of them
}
