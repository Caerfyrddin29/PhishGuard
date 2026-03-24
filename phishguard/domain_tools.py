from __future__ import annotations

from functools import lru_cache

# ISO ccTLDs + UK alias expected by users.
_CC_TLDS = {
    'ac','ad','ae','af','ag','ai','al','am','ao','aq','ar','as','at','au','aw','ax','az',
    'ba','bb','bd','be','bf','bg','bh','bi','bj','bl','bm','bn','bo','bq','br','bs','bt','bv','bw','by','bz',
    'ca','cc','cd','cf','cg','ch','ci','ck','cl','cm','cn','co','cr','cu','cv','cw','cx','cy','cz',
    'de','dj','dk','dm','do','dz',
    'ec','ee','eg','eh','er','es','et','eu',
    'fi','fj','fk','fm','fo','fr',
    'ga','gb','gd','ge','gf','gg','gh','gi','gl','gm','gn','gp','gq','gr','gs','gt','gu','gw','gy',
    'hk','hm','hn','hr','ht','hu',
    'id','ie','il','im','in','io','iq','ir','is','it',
    'je','jm','jo','jp',
    'ke','kg','kh','ki','km','kn','kp','kr','kw','ky','kz',
    'la','lb','lc','li','lk','lr','ls','lt','lu','lv','ly',
    'ma','mc','md','me','mf','mg','mh','mk','ml','mm','mn','mo','mp','mq','mr','ms','mt','mu','mv','mw','mx','my','mz',
    'na','nc','ne','nf','ng','ni','nl','no','np','nr','nu','nz',
    'om',
    'pa','pe','pf','pg','ph','pk','pl','pm','pn','pr','ps','pt','pw','py',
    'qa',
    're','ro','rs','ru','rw',
    'sa','sb','sc','sd','se','sg','sh','si','sj','sk','sl','sm','sn','so','sr','ss','st','sv','sx','sy','sz',
    'tc','td','tf','tg','th','tj','tk','tl','tm','tn','to','tr','tt','tv','tw','tz',
    'ua','ug','uk','us','uy','uz',
    'va','vc','ve','vg','vi','vn','vu',
    'wf','ws',
    'ye','yt',
    'za','zm','zw'
}

_SECOND_LEVEL_LABELS = {'co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'gouv', 'govt'}


@lru_cache(maxsize=4096)
def split_domain(value: str) -> tuple[str, str, str]:
    value = (value or '').strip().lower().strip('.')
    if not value:
        return '', '', ''
    parts = [p for p in value.split('.') if p]
    if len(parts) < 2:
        return '', value, ''

    # Handle national multi-part suffixes like co.uk, com.br, gov.fr, etc.
    if len(parts) >= 3 and parts[-1] in _CC_TLDS and parts[-2] in _SECOND_LEVEL_LABELS:
        suffix = '.'.join(parts[-2:])
        reg = '.'.join(parts[-3:])
        sub = '.'.join(parts[:-3])
        return sub, reg, suffix

    suffix = parts[-1]
    reg = '.'.join(parts[-2:])
    sub = '.'.join(parts[:-2])
    return sub, reg, suffix


def registrable_domain(value: str) -> str:
    return split_domain(value)[1]


def suffix(value: str) -> str:
    return split_domain(value)[2]
