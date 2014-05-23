# -*- Mode: Python -*-

def elem (name, props, close=False, empty=False):
    r = []
    if close:
        r.append ('</%s' % (name,))
    else:
        r.append ('\n<%s' % (name,))        
    for kw, kv in props.iteritems():
        if kw == 'klass':
            kw = 'class'
        kv = kv.replace ('"', "&quot;")
        r.append (' %s="%s"' % (kw, kv))
    if empty:
        r.append ('/>')
    else:
        r.append ('>')
    return ''.join (r)

def elem0 (_name, **props):
    return elem (_name, props, close=False)
def elem1 (_name, **props):
    return elem (_name, props, close=True)    
def elems1 (*_names):
    return ''.join (['</%s>' % name for name in _names])
def elemz (_name, **props):
    return elem (_name, props, close=False, empty=True)

def wrapn (_name, items, **props):
    r = []
    r.append (elem0 (_name, **props))
    r.extend ([str (x) for x in items])
    r.append (elem1 (_name))
    return ''.join (r)

def wrap1 (_name, item, **props):
    return wrapn (_name, [item], **props)

def trow (*vals):
    r = ['<tr>']
    for val in vals:
        # automatically choose a class based on type
        if isinstance (val, int):
            klass = 'int'
        elif isinstance (val, float):
            klass = 'float'
            val = '%.2f' % (val,)
        else:
            klass = None
        if klass:
            r.append (wrap1 ('td', val, klass=klass))
        else:
            r.append (wrap1 ('td', val))
    r.append ('</tr>\n')
    return ''.join (r)

def thead (*cols):
    r = []
    r.append ('<thead><tr>')
    for col in cols:
        r.append ('<th>%s</th>' % (col,))
    r.append ('</tr></thead>\n')
    return ''.join (r)

def autotable (rows, use_classy_rows=False, **props):
    r = [elem0 ('table', style="width:auto", **props)]
    # no header
    for row in rows:
        if use_classy_rows:
            r.append (wrapn ('tr', trow (*row)))
        else:
            r.append (wrapn ('tr', [wrap1 ('td', x) for x in row]))
    r.append (elem1 ('table'))
    return ''.join (r)

def autorow (cols, **props):
    r = [elem0 ('table', style="width:auto", **props)]
    r.append (wrapn ('tr', [wrap1 ('td', x) for x in cols]))
    r.append (elem1 ('table'))
    return ''.join (r)

def overline (text):
    return wrap1 ('font', text, style='text-decoration: overline;')
