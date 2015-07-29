// -*- Mode: C++ -*-

// originally from here, had to tweak to get it to build.
// http://programminggenin.blogspot.com/2012/10/cons-lists-in-c.html

#include <memory>

template<typename T>
struct ConsNode;

template <typename T>
using ConsList= std::shared_ptr<const ConsNode <T> >;

template<typename T>
struct ConsNode {
public:
  ConsNode(T car=T(), ConsList<T> cdr=ConsList<T>()):_car(car),_cdr(cdr) {}
  T _car;
  ConsList<T> _cdr;
  T car(const ConsList<T> &l);
  const ConsList<T>& cdr(const ConsList<T> &l);
};

template<typename T>
const ConsList<T> cons(T car, const ConsList<T>& cdr=ConsList<T>()) {
  return std::make_shared<ConsNode<T> > (car,cdr);
}

template<typename T>
T car(const ConsList<T>&l)
{
  return l->_car;
}

template<typename T>
const ConsList<T>& cdr(const ConsList<T>&l)
{
  return l->_cdr;
}

template<class T>
bool isEmpty(const ConsList<T>&l)
{
  return !l;
}

template<typename T>
unsigned len(const ConsList<T>&l)
{
  if(isEmpty(l))
    return 0;
  return 1+len(cdr(l));
}

template<typename T>
T sum(const ConsList<T>& l)
{
  if(isEmpty(l))
    return 0;
  return car(l)+sum(cdr(l));
}


#include <iostream>

template<class T>
std::ostream& operator<<(std::ostream& o, const ConsList<T>&l)
{
  if(!isEmpty(l))
    o << car(l) << " " << cdr(l);
  return o;
}
