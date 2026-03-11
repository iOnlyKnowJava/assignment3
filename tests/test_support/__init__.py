def before(s1, s2):
    return (s1 - s2) & 0xFFFFFFFF > 0x7FFFFFFF


def after(s1, s2):
    return before(s2, s1)
