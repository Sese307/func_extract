import json
import os
import hashlib
import requests
import time
import csv
import re
import pandas as pd
from environs import Env
import subprocess
import traceback
import signal
import config
import ast
import psycopg2
import logging
from datetime import datetime
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.orm import Session, join, load_only
from sqlalchemy import create_engine
import git
from multiprocessing import Process, Manager
import threading

USER = config.USER
PASSWORD = config.PASSWORD
HOST = config.HOST
PORT = config.PORT
DATABASE = config.DATABASE

connection = psycopg2.connect(user=USER,
                              password=PASSWORD,
                              host=HOST,
                              port=PORT,
                              database=DATABASE)

cursor = connection.cursor()

Base = automap_base()
engine = create_engine(f'postgresql+psycopg2://{USER}:{PASSWORD}@{HOST}:{PORT}/{DATABASE}',
                       client_encoding='utf-8')

session = Session(engine)
Base.prepare(engine, reflect=True)
vul_func_table = Base.classes.qw_huawei_vul_func
fix_func_table = Base.classes.qw_huawei_fix_func

process_number = 8


def dump_info(folder, path, content):
    path = folder + path
    with open(path, "ab") as f:
        for line in content:
            f.write(line.encode())
        f.write('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n'.encode())


def dump_file(folder, path, content):
    path = folder + path
    with open(path, "wb") as f:
        f.write(content)


def dump_csv(cnt):
    with open("huawei_cve_patch_meta_info.csv", 'w', newline='') as fp:
        csv_w = csv.writer(fp, delimiter=',')
        csv_w.writerows(cnt)


tokens = []


def get_url_content(URL):
    page = requests.get(URL, headers={'Authorization': 'token 9a8f95b03764a919adc4d41efc079bf508d791de'})
    # print(page.content)
    return page.content


def parse_content_ctags(content, filepath):
    func_pos_mapping = {}
    pat1 = "line:[0-9]+"
    pat2 = "end:[0-9]+"

    cnt_list = content.splitlines()
    for line in cnt_list:
        func_name = line.split('\t')[0]
        start = re.search(pat1, line)
        end = re.search(pat2, line)
        if start and end:
            start = int(start[0].replace('line:', ''))
            end = int(end[0].replace('end:', ''))
            if func_name in func_pos_mapping:
                func_pos_mapping[func_name].append([start, end])
            else:
                func_pos_mapping[func_name] = [[start, end]]
    return func_pos_mapping


def parse_file_ctags(filepath):
    # func_p_mapping: {'phar_dir_close': [[43, 55]], 'phar_dir_read': [[93, 125]], 'phar_dir_write': [[131, 134]],
    #                  'phar_add_empty': [[152, 157]]}
    # func_v_mapping: {'phar_dir_close': [[43, 55]], 'phar_dir_read': [[93, 125]], 'phar_dir_write': [[131, 134]],
    #                  'phar_add_empty': [[152, 157]]}
    cmd = f"../ctags/ctags --fields=+ne -o - --sort=no --c-types=f \"{filepath}\""
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    stdout = stdout.decode("utf-8")
    func_pos_mapping = None
    if stdout:
        func_pos_mapping = parse_content_ctags(stdout, filepath)

    return func_pos_mapping


def parse_content(content, filepath):
    func_pos_mapping = {}
    lines = content.split('\n')
    for i in range(len(lines)):
        line_data = lines[i]
        if line_data.find(filepath) != -1:
            try:
                funcname = (lines[i + 2]).strip()
                funcname = funcname.replace(' ', '')
                funcname = funcname.replace(':', '')
                funcname = funcname.replace('(', '')
                funcname = funcname.replace(')', '')
                funcname = funcname.replace('/', '')

                pos_line = (lines[i + 3]).strip()
                pos_arr = pos_line.split('\t')
                start_pos = int(pos_arr[0])
                end_pos = int(pos_arr[1])

                pos_info = [start_pos, end_pos]
                if funcname in func_pos_mapping:
                    func_pos_mapping[funcname].append(pos_info)
                else:
                    func_pos_mapping[funcname] = [[start_pos, end_pos]]
            except Exception as e:
                pass
    # print(func_pos_mapping)
    return func_pos_mapping


def parse_file(filepath):
    process = subprocess.Popen(['java', "-Xmx1024m", "-jar", "FuncParser-opt.jar", filepath], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    stdout = stdout.decode("utf-8")
    func_pos_mapping = None
    if stdout:
        func_pos_mapping = parse_content(stdout, filepath)

    return func_pos_mapping


def get_patched_func(p_path, v_path):
    p_file = open(p_path, "rt", encoding='latin-1').readlines()
    v_file = open(v_path, "rt", encoding='latin-1').readlines()

    o_p_path = p_path.split('/')[1]
    o_v_path = v_path.split('/')[1]

    func_p_mapping = parse_file(p_path)
    func_v_mapping = parse_file(v_path)

    if (not func_p_mapping) and (not func_v_mapping):
        func_p_mapping = parse_file_ctags(p_path)
        func_v_mapping = parse_file_ctags(v_path)

    vul_func_list = []
    print(o_p_path)
    print('func_p_mapping:', func_p_mapping)
    print('func_v_mapping:', func_v_mapping)

    if func_p_mapping and func_v_mapping:
        tmp1 = set(func_p_mapping.keys()) - set(func_v_mapping.keys())
        tmp2 = set(func_v_mapping.keys()) - set(func_p_mapping.keys())
        add_delete_func = tmp1.union(tmp2)
        # processing functions both in vul and patch file
        for k, v in func_p_mapping.items():
            if k in func_v_mapping:
                func_p_range = func_p_mapping[k]
                func_v_range = func_v_mapping[k]
                short_range = len(func_v_range) if (len(func_p_range) > len(func_v_range)) else len(func_p_range)
                # processing same functions at same place
                for i in range(short_range):
                    p_start = func_p_range[i][0]
                    v_start = func_v_range[i][0]
                    p_end = func_p_range[i][1]
                    v_end = func_v_range[i][1]

                    p_str = str(p_file[p_start - 1: p_end])
                    v_str = str(v_file[v_start - 1: v_end])
                    p_re = hashlib.md5(p_str.encode())
                    v_re = hashlib.md5(v_str.encode())

                    if p_re.hexdigest() != v_re.hexdigest():
                        # dump_info(config.diff_path, o_p_path, p_file[p_start - 1: p_end])
                        # dump_info(config.diff_path, o_v_path, v_file[v_start - 1: v_end])
                        vul_func_list.append(k)
                # processing new added/ deleted functions with same name
                if len(func_v_range) > short_range:
                    for j in range(short_range, len(func_v_range)):
                        v_start = func_v_range[j][0]
                        v_end = func_v_range[j][1]
                        # dump_info(config.diff_path, o_p_path, ['dummy function'])
                        # dump_info(config.diff_path, o_v_path, v_file[v_start - 1: v_end])
                elif len(func_p_range) > short_range:
                    for j in range(short_range, len(func_p_range)):
                        p_start = func_p_range[j][0]
                        p_end = func_p_range[j][1]
                        # dump_info(config.diff_path, o_v_path, ['dummy function'])
                        # dump_info(config.diff_path, o_p_path, p_file[p_start - 1: p_end])
        # processing new added / deleted functions
        for func in add_delete_func:
            if func in func_p_mapping:
                func_p_range = func_p_mapping[func]
                for i in range(len(func_p_range)):
                    p_start = func_p_range[i][0]
                    p_end = func_p_range[i][1]
                    # dump_info(config.diff_path, o_v_path, ['dummy function'])
                    # dump_info(config.diff_path, o_p_path, p_file[p_start - 1: p_end])
            elif func in func_v_mapping:
                func_v_range = func_v_mapping[func]
                for i in range(len(func_v_range)):
                    v_start = func_v_range[i][0]
                    v_end = func_v_range[i][1]
                    # dump_info(config.diff_path, o_p_path, ['dummy function'])
                    # dump_info(config.diff_path, o_v_path, v_file[v_start - 1: v_end])
                    vul_func_list.append(func)

    return vul_func_list, config.diff_path + o_p_path


def extract(file, func_mapping, func_name, qw_id_list, tag, func_type):
    func_range = func_mapping[func_name]
    start = func_range[0][0]
    end = func_range[0][1]
    func_result = file[start - 1: end]

    dump_info_into_DB_2(start, end, func_result, qw_id_list, tag, func_name, func_type)


def get_func(path, func_dict, func_type, tag):
    jar_tool = True
    start = 0
    end = 0
    file = open(path, "rt", encoding='latin-1').readlines()
    func_mapping_jar = parse_file(path)
    func_mapping_ctags = parse_file_ctags(path)

    for func_name, qw_id_list in func_dict.items():
        if func_mapping_jar and (func_name in func_mapping_jar):
            extract(file, func_mapping_jar, func_name, qw_id_list, tag, func_type)
        elif func_mapping_ctags and (func_name in func_mapping_ctags):
            extract(file, func_mapping_ctags, func_name, qw_id_list, tag, func_type)

    return True


def get_vul_fix_func(index, func_list, lib_id, repo_path, tag):
    meta_info = []
    for func_info in func_list:
        func_type = func_info[0]
        file = func_info[1].replace('||', '/')
        func_dict = func_info[2]
        full_path = os.path.join(repo_path, file)

        if os.path.isfile(full_path):
            # get vul func
            get_func(full_path, func_dict, func_type, tag)

    return True


# REPO MATCHING PATTERS
PATTERNS = (
    # git@host:owner/repo(.git)?
    r'^.+@(?P<host>[\w\d\.\-]+):(?P<owner>[\w\d\.\-]+)/(?P<repo>[\w\d\.\-]+)/?$',
    # https://host:(owner/)?repo(.git)?, https://host/owner/repo(.git)?
    r'^.+://:?(?P<host>[\w\d\.\-]+)/(?:(?P<owner>[\w\d\.\-~]+)/)?(?P<repo>[\w\d\.\-]+)/?$',
    # https://host/subspace(s)/owner/repo(.git)?
    r'^.+://:?(?P<host>[\w\d\.\-]+)/(?P<subspace>[\w\d\.\-~]+)/(?:(?P<owner>[\w\d\.\-~]+)/)?(?P<repo>[\w\d\.\-/]+)/?$'
)

skip_list = ['git://git.linux-nfs.org/projects/steved/nfs-utils', 'git://git.savannah.nongnu.org/lwip',
             'git://git.savannah.gnu.org/bash', 'git://sourceware.org/git/elfutils',
             'git://git.postgresql.org/git/postgresql', 'git://git.netfilter.org/iptables',
             'git://anongit.freedesktop.org/fontconfig', 'git://git.musl-libc.org/musl',
             'git://git.kernel.org/pub/scm/utils/kernel/kexec/kexec-tools', 'git://anongit.freedesktop.org/libjpeg',
             'git://git.busybox.net/busybox', 'git://git.code.sf.net/p/libpng/code', 'git://sourceware.org/git/lvm2',
             'git://git.savannah.gnu.org/readline',
             'git://git.samba.org/cifs-utils', 'git://git.savannah.gnu.org/gzip',
             'git://git.sv.gnu.org/freetype/freetype2', 'git://git.linux-nfs.org/projects/steved/libtirpc',
             'git://git.sv.gnu.org/grep', 'git://w1.fi/srv/git/hostap',
             'git://git.kernel.org/pub/scm/utils/cryptsetup/cryptsetup.git', 'git://sourceware.org/git/binutils-gdb',
             'git://git.netfilter.org/conntrack-tools']


def standardize_url(url):
    """ For a given url, returns formatted repo_url and homepage_url
        Note: Only works for Github urls
    """
    if url in skip_list:
        return url
    homepage_url, repo_url = None, None
    try:
        host, subspace, owner, repo = None, None, None, None
        for pattern in PATTERNS:
            res = re.match(pattern, url)
            if res:
                break
        # 'subspace' is not a fixed group, try matching
        # If it fails, ignore
        try:
            subspace = res.group('subspace')
        except:
            pass

        # If none of the patterns match, exception logged after this
        host, owner, repo = (res.group('host'),
                             res.group('owner'),
                             res.group('repo'))
        if repo.endswith('.git'):
            repo = repo[:-4]

        if owner and subspace:
            homepage_url = f'https://{host}/{subspace}/{owner}/{repo}'
            repo_url = f'git://{host}/{subspace}/{owner}/{repo}'
        elif owner and not subspace:
            if 'github' in host:
                repo_url = f'git@{host}:{owner}/{repo}.git'
            else:
                repo_url = f'git://{host}/{owner}/{repo}'
            homepage_url = f'https://{host}/{owner}/{repo}'
        elif not (owner or subspace):
            homepage_url = f'https://{host}/{repo}'
            repo_url = f'git://{host}/{repo}'
    except Exception as e:
        print(f'Bad url {url}: {e}')
    return homepage_url


def get_tag(url):
    cmd = f"git -c 'versionsort.suffix=-' ls-remote --tags --refs {url}"  #
    p = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid
    )
    try:
        out, err = p.communicate(timeout=10)
        tag_list = out.decode().splitlines()
        if not tag_list:
            print(tag_list, url)
        return tag_list
    except Exception as e:
        result = {"error": traceback.format_exc()}
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        print(result)
        return False


def clean_tag(tag_list):
    return [item.split('tags/')[-1] for item in tag_list]

def chunk_it(seq, chunk_number):
    return list((seq[i::chunk_number] for i in range(chunk_number)))
#
# # create folder
# if not os.path.exists(config.vul_file_path):
#     os.mkdir(config.vul_file_path)
# if not os.path.exists(config.vul_func_path):
#     os.mkdir(config.vul_func_path)
# if not os.path.exists(config.diff_path):
#     os.mkdir(config.diff_path)
#


def dump_info_into_DB_1(lib_id, cve, file_pair, vul_func_list, vul_tag_list, fix_tag_list, session, func_table):
    list_insert = []
    record = {
        'library_id': int(lib_id),
        'cve': cve,
        'patched_file_path': file_pair[0],
        'vul_file_path': file_pair[1],
        'vul_func_list': vul_func_list,
        'vul_tag_list': vul_tag_list,
        'fix_tag_list': fix_tag_list,
        'extract_method': 'jar tool',
        'is_valid': True
    }
    list_insert.append(record)
    session.bulk_insert_mappings(func_table, list_insert)
    session.commit()


def dump_info_into_DB_2(start, end, func_result, qw_id_list, tag, func_name, func_type):
    tmp = ''.encode()
    for line in func_result:
        tmp += line.encode()
    record = {
        'tag': tag,
        'func_name': func_name,
        'func_hunk': tmp,
        'qhvftf_id': list(set(qw_id_list)),
        'func_start': start,
        'func_end': end,
        'is_valid': True
    }
    if func_type == 'vul':
        vul_func_list.append(record)
    elif func_type == 'fix':
        fix_func_list.append(record)


def extract_diff_func():
    engine = create_engine(f'postgresql+psycopg2://{USER}:{PASSWORD}@{HOST}:{PORT}/{DATABASE}',
                           client_encoding='utf-8')
    session = Session(engine)
    Base.prepare(engine, reflect=True)
    func_table = Base.classes.qw_huawei_vul_file_tag_func
    # get all files
    all_file_list = []
    for root, dirs, files in os.walk(config.patch_vul_path):
        for file in files:
            # print(file)
            if file.endswith(".c") or file.endswith(".cpp") or file.endswith(".cc") or file.endswith(".cxx"):
                file_path = os.path.join(root, file)
                all_file_list.append(file_path)

    # get patch/vul file pair
    file_pair = []
    for file in all_file_list:
        if "_patch___" in file:
            tmp_tag = file.replace("_patch___", "_vul___")
            for file2 in all_file_list:
                if tmp_tag in file2:
                    file_pair.append([file, file2])
                    break

    # # get vul tags for CVEs
    # cve_vul_tags = json.load(open("CVE_VUL_TAGS.json", 'r'))
    # cve_fix_tags = json.load(open("CVE_FIX_TAGS.json", 'r'))
    # cve_list = ['CVE-2013-4122']
    for item in file_pair:
        # print("comparing : ", item)
        patched_file = item[0]
        vul_file = item[1]
        cve = patched_file.split('/')[-1].split('||')[0]
        # if not cve in cve_list:
        #     continue
        lib_id = patched_file.split('/')[-1].split('||')[1]
        # check if item has been processed
        cursor.execute(
            f"select id from qw_huawei_vul_file_tag_func where library_id={lib_id} and cve='{cve}' and patched_file_path='{patched_file}'")
        result = cursor.fetchone()
        if result:
            continue
        print("processing: ", cve)

        # # get vul tags
        # vul_tag_list = []
        # vul_lib_tag = cve_vul_tags.get(cve, {})
        # if vul_lib_tag:
        #     vul_tag_list = vul_lib_tag.get(lib_id, [])
        # # get fix tags
        # fix_tag_list = []
        # fix_lib_tag = cve_fix_tags.get(cve, {})
        # if fix_lib_tag:
        #     fix_tag_list = fix_lib_tag.get(lib_id, [])

        vul_func_list, patched_func_path = get_patched_func(patched_file, vul_file)
        dump_info_into_DB_1(lib_id, cve, item, vul_func_list, [], [], session, func_table)


def extract_func_for_one_tag(tag_groups, lib_id, repo_path, tag):
    global vul_func_list
    global fix_func_list

    manager = Manager()
    vul_func_list = manager.list()
    fix_func_list = manager.list()

    jobs = []
    for x in range(len(tag_groups)):
        thread = Process(
            target=get_vul_fix_func, args=(x + 1, tag_groups[x], lib_id, repo_path, tag))
        jobs.append(thread)
        thread.start()

    for proc in jobs:
        proc.join()
    session.bulk_insert_mappings(vul_func_table, vul_func_list)
    session.bulk_insert_mappings(fix_func_table, fix_func_list)
    session.commit()


def format_info(input):
    output = {}
    for file_func, qw_id_list in input.items():
        # tag_batch.append(["vul", file_func, qw_id_list])
        file = '||'.join(file_func.split('||')[:-1])
        func = file_func.split('||')[-1]
        output.setdefault(file, {})[func] = qw_id_list
    return output

def get_vul_ver_func():
    # meta_info = get_all_vul_func(patched_file, vul_tag_list, vul_func_list)
    print('start')
    lib_id = 12753
    repo_path = "/home/qingwen/Desktop/linux"
    bulky_dict = {}
    cursor.execute("select id, patched_file_path, vul_func_list, vul_tag_list, fix_tag_list\
                    from qw_huawei_vul_file_tag_func\
                    where library_id=12753 and vul_func_list!='{}'")
    result = cursor.fetchall()
    print(len(result))

    for item in result:
        func_list = item[2]
        for func in func_list:
            file_func = item[1].split("_patch___")[-1] + '||' + func
            for vul_ver in item[3]:
                if vul_ver not in bulky_dict:
                    bulky_dict[vul_ver] = {"vul": {}, "fix": {}}
                    bulky_dict[vul_ver]["vul"].setdefault(file_func, []).append(item[0])
                else:
                    bulky_dict[vul_ver]["vul"].setdefault(file_func, []).append(item[0])
            for fix_ver in item[4]:
                if fix_ver not in bulky_dict:
                    bulky_dict[fix_ver] = {"vul": {}, "fix": {}}
                    bulky_dict[fix_ver]["fix"].setdefault(file_func, []).append(item[0])
                else:
                    bulky_dict[fix_ver]["fix"].setdefault(file_func, []).append(item[0])

    print(len(bulky_dict))

    for tag, func_info in bulky_dict.items():
        if tag < 'v4' or tag > 'v4.5':
            continue
        # check if tag has been processed or not
        cursor.execute(f"select id from qw_huawei_vul_func where tag ='{tag}'")
        r = cursor.fetchone()
        if r:
            continue
        # checkout to specific tag
        try:
            git.Git(repo_path).checkout(tag, force=True)
            print("Processing:", lib_id, tag)
            tag_batch = []
            # process vul func dict
            vul_func_dict = func_info.get("vul", {})
            if vul_func_dict:
                tmp_dict = format_info(vul_func_dict)
                if tmp_dict:
                    for file, info in tmp_dict.items():
                        tag_batch.append(["vul", file, info])
            # process fix func dict
            fix_func_dict = func_info.get("fix", {})
            if fix_func_dict:
                tmp_dict = format_info(fix_func_dict)
                if tmp_dict:
                    for file, info in tmp_dict.items():
                        tag_batch.append(["fix", file, info])

            tag_task_groups = chunk_it(tag_batch, process_number)
            extract_func_for_one_tag(tag_task_groups, lib_id, repo_path, tag)
            # break
        except:
            open("failed_checkout_tag.txt", "a").write(f"{lib_id}\t{tag}\n")


if __name__ == '__main__':
    get_vul_ver_func()
