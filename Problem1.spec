# -*- mode: python -*-

block_cipher = None


a = Analysis(['Problem1.py'],
             pathex=['/Users/akshaybudhkar/Desktop/cryptography_project/Budhkar_Akshay_N1501593F'],
             binaries=None,
             datas=None,
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='Problem1',
          debug=False,
          strip=False,
          upx=True,
          console=True )
