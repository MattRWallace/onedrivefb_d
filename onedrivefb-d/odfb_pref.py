#!/usr/bin/python3

"""
Preference guide dispatcher for onedrive-d.
"""

import argparse
import os


def main():
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    pref_guide = None

    # TODO: Fix the documentation here
    parser = argparse.ArgumentParser(prog='onedrive-pref',
        description='Configuration guide for onedrive-d program.',
        epilog=('For technical support, '
                'visit http://github.com/xybu/onedrive-d/issues.'))

    parser.add_argument('--ui', default='cli',
                        choices=['cli', 'gtk'],
                        help='specify the user interface. Default: cli')

    args = parser.parse_args()

    if args.ui == 'gtk':
        import odfb_pref_gtk
        pref_guide = odfb_pref_gtk.PreferenceGuide()
    else:
        import odfb_pref_cli
        pref_guide = odfb_pref_cli.PreferenceGuide()

    pref_guide.start()

if __name__ == "__main__":
    main()
