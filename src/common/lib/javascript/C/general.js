/*
 * General Utilities for JS Object Management
 * (c) by Massimiliano Pala and OpenCA Labs
 * OpenCA Licensed Software
 */

/* Object Prototype: Adds the possibility to easily specify the prototype
 *                   in object creation */

if(typeof Object.create !== 'function') {
	Object.create = function(o) {
		var F = function() {};
		F.prototype = o;
		return new F();
	}
};

/* Object Prototype: Provides an easy syntax for adding a method to the
 *                   Object type */

Object.prototype.method = function(name, func) {
	if (!this.prototype[name]) {
		this.prototype[name] = func;
		return this;
	}
};

/* Object Method: Adds the possibiltiy to retrieve the array of properties
 *                of an Object */

Object.method('getProperties', function() {
	ret = [];

	for(name in this) {
		if(typeof this[name] !== 'function') {
			ret.push(this[name]);
		}
	}

	return ret;
});

/* Object Method: Adds the possibiltiy to retrieve the array of names of
 *                the Object's properties */

Object.method('getPropertyNames', function() {
	ret = [];

	for(name in this) {
		if(typeof this[name] !== 'function') {
			ret.push(name);
		}
	}

	return ret;
});

/* Function Prototype: Provides an easy syntax for adding a method to the
 *                     Function type */

Function.prototype.method = function(name, func) {
	if (!this.prototype[name]) {
		this.prototype[name] = func;
		return this;
	}
};

/* Function prototype: Adds the possibility to specify inheritance */

Function.method('inherits', function() {
	this.prototype = new Parent();
	return this;
});

/* Adds the method to the Number type - returns the integer part */

Number.method('integer', function() {
	return Math[this < 0 ? 'ceil' : 'floor'](this);
});

/* Returns a literal object with all the parsed info from the url */

String.method('parseURL', function() {
	var parse_url = /^(?:([A-Za-z]+):)?(\/{0,3})([0-9.\-A-Za-z]+)(?::(\d+))?(?:\/([^?#]*))?(?:\?([^#]*))?(?:#(.*))?$/;

	var results = parse_url.exec( this );

	return {
		"url": results[0],
		"scheme": results[1],
		"slash": results[2],
		"host": results[3],
		"port": results[4],
		"path": results[5],
		"query": results[6],
		"hash": results[7],
	}
});

