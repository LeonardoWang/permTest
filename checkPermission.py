import os
import zipfile
import sys

from libdex import dex
import library
total_permission_list = []
usage_perm_list = []
perm_map = {}
def get_permission(content):
    perm_list = content.split('\n')
    for perm_value in perm_list:
        if perm_value.find('uses-permission') >= 0:
            now_perm = perm_value.replace('uses-permission: name=','')
            now_perm = now_perm.replace('\'','')
            total_permission_list.append(now_perm)
        elif perm_value.find('permission:') >= 0:
            now_perm = perm_value.replace('permission:','')
            total_permission_list.append(now_perm)

def get_method_perm(file_path):
    f = open(file_path)
    for lines in f.readlines():
        now_line = lines.strip().split('  ::  ')
        if len(now_line)==2:
            perm_map[now_line[0]] = now_line[1]

def get_dex_file(filepath):
    permission_content = os.popen('./tools/aapt dump permissions {}'.format(filepath)).read()
    print(permission_content)

    apkfile = zipfile.ZipFile(filepath,'r')
    if os.path.isdir('dex') == False:
        os.mkdir('dex')
    for tempfile in apkfile.namelist():
        if tempfile.endswith('.dex'):
            #print(tempfile)
            dexfilename = 'dex/tmpdex.dex'
            
            dex_file = open(dexfilename,'wb+')
            dex_file.write(apkfile.read(tempfile))
            dex_info = dex.Dex(dexfilename)
            if hasattr(dex_info, 'classes'):
                for class_ in dex_info.classes:
                    print(class_.name())
                    for method in class_.methods():
                        #print('method', method.name())
                        now_perm = perm_map.get(method, None)
                        if now_perm is not None and now_pem not in usage_perm_list:
                            usage_perm_list.append(now_perm)
            print(usage_perm_list)
            library_list = library.detect_exact_dex_libraries(dex_info)
            print(library_list)

get_method_perm('./tools/framework-map-25.txt')
get_method_perm('./tools/sdk-map-25.txt')
get_dex_file(sys.argv[1])

