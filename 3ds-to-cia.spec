# -*- mode: python -*-

import sys
import platform

def get_tools_path():
    bits = "64" if platform.machine().endswith("64") else "32"

    if sys.platform == "win32":
        return [( os.path.join("tools", "win32"), os.path.join("tools", "win32") ),
		( os.path.join("tools", "win64"), os.path.join("tools", "win64") )]

    print "Sorry, your OS is not supported yet."
    sys.exit(1)

block_cipher = None

a = Analysis(['3ds-to-cia.py'],
             binaries=get_tools_path(),
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
          name='3ds-to-cia',
          debug=False,
          strip=False,
          upx=True,
          console=True )
