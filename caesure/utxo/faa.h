// -*- Mode: C++; -*-

#include <cassert>
#include <memory>
#include <list>
#include "cons.h"

template<typename T, typename Compare = std::less<T>>
class FAA
{
private:
  struct Node;
  typedef std::shared_ptr<const Node> pNode;
  pNode _node;

  typedef uint8_t level_t;

  struct Node {
    Node (level_t level, pNode const & l, pNode const & r, T val)
      : _level(level), _l(l), _r(r), _val(val) {}
    Node () {}
    level_t _level;
    pNode _l;
    pNode _r;
    T _val;
  };

  static
  bool
  Equals (const T & a, const T & b)
  {
    return (!Compare() (a, b) && !Compare() (b, a));
  }

  struct Remover {
    pNode _heir;
    pNode _item;
    T _removed;
    T _swap;
    bool _found;
  };

  typedef ConsList<pNode> path_t;

public:

  // an iterator contains a copy of the path from the root to the current position,
  //   so a live iterator holds a reference to that entire tree's state (and will
  //   thus keep that entire version of the tree from going away).

  class iterator {

  private:
    path_t _path;

  public:

    // these typedefs provide enough magic to allow
    //   this iterator to work with STL.
    typedef std::ptrdiff_t difference_type;
    typedef T value_type;
    typedef const T& reference;
    typedef const T* pointer;
    typedef std::input_iterator_tag iterator_category;

    iterator (path_t & path) : _path(path) {}
    iterator() {}

    bool
    operator!=(const iterator & other) const
    {
      return _path != other._path;
    }

    bool
    operator==(const iterator & other) const
    {
      return _path == other._path;
    }

    const iterator &
    operator++()
    {
      path_t p = _path;
      if (!p) {
	return *this;
      } else {
	pNode n = car (p);
	if (n->_r->_level) {
	  n = n->_r;
	  p = cons (n, p);
	  while (n->_l->_level > 0) {
	    n = n->_l;
	    p = cons (n, p);
	  }
	  _path = p;
	  return *this;
	} else {
	  pNode child = n;
	  while (true) {
	    if (cdr(p)) {
	      p = cdr(p);
	      n = car(p);
	      if (child == n->_l) {
		_path = p;
		return *this;
	      }
	      child = n;
	    } else {
	      path_t p;
	      _path = p;
	      return *this;
	    }
	  }
	  _path = p;
	  return *this;
	}
      }
    }

    // Note: operator-- would be a mirror image of operator++, swapping all the
    //   rights and lefts.  A proper iterator implementation would do rbegin/rend/etc.
    //   Also, note that "end()--" is supposed to give you the last element.

    const T & operator*()
    {
      return car(_path)->_val;
    }

    // make a copy of the tree from this node up, replacing the value
    //  stored here with a new value.
    const pNode replace (T val)
    {
      T val0 = val; // copy?
      auto path = _path;
      auto node0 = car (path);
      auto node1 = set_val (node0, val0);
      while (cdr(path)) {
	path = cdr (path);
	auto parent = car (path);
	if (parent->_l == node0) {
	  node1 = set_l (parent, node1);
	} else {
	  node1 = set_r (parent, node1);
	}
	node0 = parent;
      }
      return node1;
    }

    const void dump_path() const
    {
      std::cerr << "( ";
      auto path = _path;
      while (path) {
	std::cerr << car(path).get() << " ";
	path = cdr (path);
      }
      std::cerr << " )";
    }

    unsigned depth()
    {
      return len(_path);
    }

  };

  static pNode _nil;

  // tricky making the sentinel that points at itself.
  static
  pNode
  make_nil()
  {
    Node * nil = new Node;
    nil->_level = 0;
    nil->_l = std::shared_ptr<const Node>(nil);
    nil->_r = std::shared_ptr<const Node>(nil);
    return nil->_l;
  }

  static
  pNode
  make (level_t level, pNode const & l, pNode const & r, T val)
  {
    return std::make_shared<const Node>(level, l, r, val);
  }

  static
  pNode
  build0 (T*(next)(), unsigned int lo, unsigned int hi)
  {
    if (hi == lo) {
      return _nil;
    } else {
      unsigned int mid = ((hi - lo) / 2) + lo;
      pNode l = build0 (next, lo, mid);
      //T * elem = next();
      T elem = *next();
      pNode r = build0 (next, mid + 1, hi);
      return make (l->_level + 1, l, r, elem);
    }
  }

  template<class I>
  static
  pNode
  build1 (I & i, unsigned int lo, unsigned int hi)
  {
    if (hi == lo) {
      return _nil;
    } else {
      unsigned int mid = ((hi - lo) / 2) + lo;
      pNode l = build1 (i, lo, mid);
      T elem = *i;
      ++i;
      pNode r = build1 (i, mid + 1, hi);
      return make (l->_level + 1, l, r, elem);
    }
  }

  explicit FAA (pNode const & node) : _node(node) {}

  static
  pNode
  skew (pNode const & n)
  {
    if (n->_level != 0) {
      if (n->_l->_level == n->_level) {
	return make (
	  n->_level,
	  n->_l->_l,
	  skew (set_l (n, n->_l->_r)),
	  n->_l->_val
	);
      } else {
	return set_r (n, skew (n->_r));
      }
    } else {
      return n;
    }
  }

  static
  pNode
  split (pNode n)
  {
    if ((n->_level != 0) && (n->_r->_r->_level == n->_level)) {
      return make (
	n->_r->_level + 1,
	set_r (n, n->_r->_l),
	split (n->_r->_r),
	n->_r->_val
      );
    } else {
      return n;
    }
  }

  static
  pNode
  insert0 (pNode n, T val0)
  {
    if (n->_level == 0) {
      return make (1, _nil, _nil, val0);
    } else if (Compare() (n->_val, val0)) {
      return split (skew (set_r (n, insert0 (n->_r, val0))));
    } else {
      return split (skew (set_l (n, insert0 (n->_l, val0))));
    }
  }

  static
  void
  verify0 (pNode n)
  {
    if (n->_level != 0) {
      verify0 (n->_l);
      assert (n->_l->_level != n->_level);
      assert (!((n->_level == n->_r->_level) && (n->_level == n->_r->_r->_level)));
      verify0 (n->_r);
    }
  }

  static
  void
  dump0 (pNode n, int depth)
  {
    if (n->_l != _nil) {
      dump0 (n->_l, depth + 1);
    }
    std::cerr << n;
    for (int i=0; i < depth; i++) {
      std::cerr << "  ";
    }
    std::cerr << n->_val << "\n";
    if (n->_r != _nil) {
      dump0 (n->_r, depth + 1);
    }
  }

  // emulate mutability in order to simplify the following code.
  // [xxx might it be possible to have non-const Node, then modify it, then wrap it in const later?
  //   might cut down on all the likely copies generated here...]
  static pNode set_level (pNode n, level_t level) {return make (level, n->_l, n->_r, n->_val);}
  static pNode set_l     (pNode n, pNode l)       {return make (n->_level, l, n->_r, n->_val);}
  static pNode set_r     (pNode n, pNode r)       {return make (n->_level, n->_l, r, n->_val);}
  static pNode set_val   (pNode n, T & val)       {return make (n->_level, n->_l, n->_r, val);}

  static
  pNode
  remove0 (Remover & r, pNode root, T & key)
  {
    pNode root0;

    if (root == _nil) {
      return root;
    } else {
      // --- descend ---
      r._heir = root;
      if (!Compare() (root->_val, key)) {	// i.e., >=
	// this is set on each right turn
	r._item = root;
	root0 = set_l (root, remove0 (r, root->_l, key));
	if (r._found && (r._item == root)) {
	  // do the swap
	  root0 = set_val (root0, r._swap);
	}
      } else {
	root0 = set_r (root, remove0 (r, root->_r, key));
      }
      // --- ascend ---
      if (root == r._heir) {
	// at the bottom, remove
	if (r._item && Equals (r._item->_val, key)) {
	  r._removed = r._item->_val;
	  r._swap = root->_val;
	  r._found = true;
	  // here we differ from AA's algorithm
	  if (root0->_r == _nil) {
	    return root0->_l;
	  } else {
	    return root0->_r;
	  }
	} else {
	  return root0;
	}
      } else {
	// not at the bottom, check balance
	if ((   root0->_l->_level < (root0->_level - 1))
	    || (root0->_r->_level < (root0->_level - 1))) {
	  root0 = set_level (root0, root0->_level - 1);
	  if (root0->_r->_level > root0->_level) {
	    // equivalent to root0.r.level = root0.level
	    root0 = set_r (root0, set_level (root0->_r, root0->_level));
	  }
	  return split (skew (root0));
	} else {
	  return root0;
	}
      }
    }
  }

  static
  iterator
  find0 (pNode n, const T & x, path_t & p)
  {
    if (n->_level == 0) {
      return iterator();
    } else {
      p = cons (n, p);
      if (Compare() (x, n->_val)) {
	return find0 (n->_l, x, p);
      } else if (Compare() (n->_val, x)) {
	return find0 (n->_r, x, p);
      } else {
	return iterator (p);
      }
    }
  }

  static
  uint32_t
  size0 (pNode n, uint32_t acc)
  {
    if (n->_level == 0) {
      return acc;
    } else {
      return size0 (n->_l, size0 (n->_r, acc+1));
    }
  }

public:

  FAA() : _node (_nil)
  {}

  FAA (level_t level, FAA const & l, FAA const & r, T val)
    : _node (std::make_shared<const Node>(level, l._node, r._node, val))
  {}

  // populate an FAA from iterators.
  template<class I>
  FAA (I b, I e)
  {
    FAA t;
    for_each(b, e, [&t](T const & v){
	t = t.insert(v);
      });
    _node = t._node;
  }

  // build a complete-ish tree from sorted input via funcall.
  FAA (T*(next)(), unsigned int lo, unsigned int hi)
    : _node (build0 (next, lo, hi)) {}

  // build a complete-ish tree from sorted input via iterator.
  template<class O>
  FAA (O & o, unsigned int lo, unsigned int hi) {
    typename O::iterator b = o.begin();
    _node = build1 (b, lo, hi);
  }

  bool is_empty() const { return _node == _nil; }

  T
  val() const
  {
    assert (!is_empty());
    return _node->_val;
  }

  level_t level() const {return _node->_level;}
  FAA left() const {return FAA (_node->_l);}
  FAA right() const {return FAA (_node->_r);}

  FAA insert (T val0)  const
  {
    return FAA (insert0 (_node, val0));
  }

  // I think this would traditionally return an iterator. TBD.
  FAA remove (T val0, bool & found, T & removed) const
  {
    found = false;
    Remover r;
    pNode result = remove0 (r, _node, val0);
    if (r._found) {
      removed = r._removed;
      found = true;
      return FAA (result);
    } else {
      return *this;
    }
  }

  // replace an item (useful when modifying the value portion of a key/value pair).
  FAA replace (iterator i, T item)
  {
    assert (!Compare()(*i, item));
    return FAA (i.replace (item));
  }

  void
  verify()
  {
    verify0 (_node);
  }

  void
  dump (int d=1)
  {
    if (level() != 0) {
      left().dump (d+1);
      for (int i=0; i < d; i++) {
	std::cerr << "  ";
      }
      std::cerr << (int)level() << ":" << val() << std::endl;
      right().dump (d+1);
    }
  }

  const iterator
  begin() const
  {
    pNode n = _node;
    path_t p;
    while (n->_level > 0) {
      p = cons (n, p);
      n = n->_l;
    }
    return iterator (p);
  }

  const iterator
  end() const
  {
    path_t p;
    return iterator(p);
  }

  const iterator
  find (const T & x) const
  {
    path_t null_path;
    return find0 (_node, x, null_path);
  }

  uint32_t
  size()
  {
    return size0 (_node, 0);
  }

};

template<typename T, typename C>
typename FAA<T,C>::pNode FAA<T,C>::_nil = FAA<T,C>::make_nil();
