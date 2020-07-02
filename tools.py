import nacl.public, nacl.encoding
import os

def create_keys(fullname):
    ''' Create secret and public keys for nacl
    
        The keys are stored in path in hexencoding where
        path,name = os.split(fullname)
        
        If path does not exist, raise an error
        If path has wrong permissions, raise an error:
        Only onwner can read,write or execute path (i.e. chmod path og-rwx)
        
        The permissions of the resulting secret keyfile is og-rwx
        (Only owner can read,write or execute secret keyfile)
    '''
    path,name = os.path.split(fullname)
    pub_name = fullname+'.pub'
    
    assert os.path.exists(path), f'path does not exist: {path}'
    assert os.stat(path).st_mode & 0o700, f'wrong permission on path: {path}'
    
    with open(fullname,'w') as s_f, open(pub_name,'w') as p_f:
        key = nacl.public.PrivateKey.generate()
        
        s_f.write(key.encode(nacl.encoding.HexEncoder).decode())
        p_f.write(key.public_key.encode(nacl.encoding.HexEncoder).decode())
        
    os.chmod(fullname,0o700)

def read_secret_key(fullname):
    ''' Read a private key for nacl from fullname.
        The path and the fullname must have the right permissions, og-rwx
        (Only user can read,write or execute secret key)
    '''
    path,name = os.path.split(fullname)
    assert os.stat(path).st_mode & 0o700, f'wrong permission on path {path}'
    assert os.stat(fullname).st_mode & 0o700, f'wrong permission on file {fullname}'
    
    with open(fullname,'r') as f:
        key = nacl.public.PrivateKey(f.read().encode(),encoder=nacl.encoding.HexEncoder)
        
    return key

def read_public_key(fullname):
    ''' Read a public key for nacl from fullname'''
    
    with open(fullname,'r') as f:
        key = nacl.public.PublicKey(f.read().encode(),encoder=nacl.encoding.HexEncoder)
    
    return key

def encrypt(sk,pk,f_in_name,f_out_name):
    ''' encrypt f_in_name to f_out_name using nacl with 
        secret key sk and public key pk
    '''
    with open(f_in_name,'rb') as f_in, open(f_out_name,'wb') as f_out:
        f_out.write(nacl.public.Box(sk,pk).encrypt(f_in.read()))


def decrypt(sk,pk,f_in_name,f_out_name):
    ''' decrypt f_in_name to f_out_name using nacl with
        secret key sk und public key pk
    '''
    with open(f_in_name,'rb') as f_in, open(f_out_name,'wb') as f_out:
        f_out.write(nacl.public.Box(sk,pk).decrypt(f_in.read()))
