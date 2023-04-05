#! /usr/bin/env python3

from github import Github
import os
import re
import shutil
import subprocess
import sys



def usage():
    print('usage: {} <repo> <path> <version> <asset_url_prefix>'.format(sys.argv[0]))
    exit(1)


def new_github_repository_instance(repository, token, username):
    github_client = Github(token)
    github_user = github_client.get_user(username)
    return github_user.get_repo(repository)


# DOCS: https://pygithub.readthedocs.io/en/latest/github_objects/Repository.html#github.Repository.Repository.create_git_release
def create_github_release(gh_repo, release_name, assets_url_prefix=None):
    releases = gh_repo.get_releases()

    release = None
    for r in releases:
        if r.tag_name == release_name:
            release = r
            break

    tag = release_name
    name = release_name
    description_lines = [ '#### Version {}'.format(release_name) ]

    if assets_url_prefix is not None:
        for folder_entry in os.listdir(assets_directory_path):
            if folder_entry.endswith('.sum'):
                artifact_name =  '.'.join(folder_entry.split('.')[:-1])
                artifact_file_name = '{}.tar.gz'.format(artifact_name)
                checksum_file_path = os.path.join(assets_directory_path, folder_entry)

                checksum = 'N/A'
                with open(checksum_file_path) as checksum_file:
                    checksum = checksum_file.readline().strip()
                markdown_template = '`{}` - [{}]({}/{})'
                description_lines.append(markdown_template.format(
                    checksum,
                    artifact_file_name,
                    assets_url_prefix,
                    artifact_file_name
                ))

    description = os.linesep.join(description_lines)

    if release is None:
        release = gh_repo.create_git_release(tag, name, description)
    else:
        print('[INFO] Release: {} already exists, aborting'.format(release_name))

    if assets_url_prefix is None:
        for folder_entry in os.listdir(assets_directory_path):
            print('Uploading {} as asset to release {}'.format(folder_entry, name))
            asset_path = os.path.join(assets_directory_path, folder_entry)
            release.upload_asset(asset_path)


if len(sys.argv) < 4:
    usage()

repository_name = sys.argv[1]
assets_directory_path = sys.argv[2]
version = sys.argv[3]
s3_bucket_folder_url = None

if len(sys.argv) == 5:
    s3_bucket_folder_url = sys.argv[4]

gh_user = os.getenv('GITHUB_USER', 'wearezeta')
gh_token = os.environ.get('GITHUB_TOKEN')


github_repo = new_github_repository_instance(repository_name, gh_token, gh_user)

create_github_release(github_repo, version, s3_bucket_folder_url)
