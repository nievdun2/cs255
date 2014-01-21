/*
  CS255 - Winter 2014
  Assignment 1: S/KEY Authentication
  Starter Code Version: 1.0

  SUNet ID #1: macqueen
  SUNet ID #2: rmferrer

  Step 1: Find a project partner and add your SUNet IDs above.
  Step 2: Implement `initialize`, `advance`, `save`, and `load` in `pebble_chain`.
  Step 3: Answer the questions below.
  Step 4: See Piazza for submission instructions.
*/

/* 1. Briefly describe your implementation and its design choices. (e.g. What algorithm did you use? How did you structure your code? Did you do something interesting in \texttt{save}/\texttt{load}? If it's not obvious, justify the space/time used by your implementation.)
// TODO: Answer here (a few sentences).
*/

/* 2. If you were designing an authentication mechanism for a hot new startup that wants to protect its users, how would you decide whether/where to use S/KEY?
// TODO: Answer here (a few sentences).
*/

/* 3. (Will not affect your grade:) How long did you spend on this project?
// TODO: Answer here (just a number).
*/

/* 4. (Optional:) Do you have any comments or suggestions for improving the assignment?
// TODO: Answer here (optional).
*/


/********* External Imports and Convenience Functions ********/


"use strict"; // Makes it easier to catch errors.

var sjcl = require("./lib/sjcl");
var hash = sjcl.hash.sha256.hash; // Hashes a string or bitArray to a bitArray.
var is_equal = sjcl.bitArray.equal; // Compares two bitArrays.
var hex = sjcl.codec.hex.fromBits; // Converts a bitArray to a hex string.

var pow2 = Math.pow.bind(this, 2); // Calculates 2 to a given power.
var log2 = function(x) {return Math.log(x) / Math.log(2);} // Calculates log base 2.


/******** Naive Hash Chain Implementation ********/


function naive_chain() {

  var chain = {
    state: null
  };

  chain.initialize = function(num_iterations, seed) {
    chain.state = {
      position: 0,
      num_iterations: num_iterations,
      start: hash(seed)
    }

    var initial = chain.state.start;
    for (var i = 0; i < chain.state.num_iterations; i++) {
      initial = hash(initial);
    }

    return initial;
  }

  chain.advance = function() {
    if (chain.state.position + 1 > chain.state.num_iterations) {
      return null;
    }

    var value = chain.state.start;
    for (var i = 1; i < chain.state.num_iterations - chain.state.position; i++) {
      value = hash(value);
    }
    chain.state.position += 1;
    return value;
  }

  // Returns a string.
  chain.save = function() {
    return JSON.stringify(chain.state);
  }

  // Loads a string.
  chain.load = function(str_data) {
    chain.state = JSON.parse(str_data);
  }

  return chain;
}


/******** Pebble-Based Hash Chain Implementation (Jakobsson's algorithm) ********/


function pebble_chain() {

  var chain = {
    state: null
  };

  function pebble(position, is_special_pebble, hash_value){
    var pebble = {
      position: position,
      is_special_pebble: is_special_pebble,
      hash_value: hash_value
    }
    return pebble
  }

  chain.is_power_of_two_from_end = function(index){
    var length_of_chain = chain.state.position;
    var dist = length_of_chain - index;
    var isPowerOf2 = (log2(dist) % 1) == 0;
    return isPowerOf2;
  }

  chain.initialize = function(num_iterations, seed) {
    var pebbles = []
    chain.state = {
      position: num_iterations,
      num_iterations: num_iterations,
      pebbles: pebbles
    }
    var start = hash(seed);

    var current_value = start;
    for (var i = 0; i < num_iterations; i++){
      if (chain.is_power_of_two_from_end(i)) {
        chain.state.pebbles.push( new pebble(i, true, current_value))
      }
      current_value = hash(current_value);
    }

    return current_value;
  }

  chain.move_pebbles = function(){

    var pebbles_to_add = [];
    var num_pebbles_added = 0;
    // Don't modify the last pebble since it will stay there to be returned next round
    for (var i = 0; i < chain.state.pebbles.length - 1; i++){
      var cur_pebble = chain.state.pebbles[i]
      // If position of this pebble is power of 2 from end,
      // we must duplicate it
      if (chain.is_power_of_two_from_end(cur_pebble.position)){
        var duplicate_pebble = pebble(cur_pebble.position, true, cur_pebble.hash_value);
        // (i + num_pebbles_added) denotes the index at which this new pebble
        // will be inserted into the pebble array
        pebbles_to_add.push([duplicate_pebble, i + num_pebbles_added])
        num_pebbles_added++;
        // Since we have now duplicated this pebble, the original is no longer
        // a 'special' pebble, since its copy is special
        chain.state.pebbles[i].is_special_pebble = false;
      }

      // Advance by one all pebbles that are not 'special' placeholders
      if (!cur_pebble.is_special_pebble){
        chain.state.pebbles[i].position++;
        chain.state.pebbles[i].hash_value = hash(chain.state.pebbles[i].hash_value)
      }

    }
    // Now add in the duplicated pebbles
    for(var k = 0; k < pebbles_to_add.length; k++){
      chain.state.pebbles.splice(pebbles_to_add[k][1], 0, pebbles_to_add[k][0]);
    }
  }

  chain.advance = function() {
    if (chain.state.position == 0) {
      return null;
    }

    // Pop the end-most pebble to retrieve its hash value to return
    var pebble_to_return = chain.state.pebbles.pop();

    chain.move_pebbles()
    chain.state.position--;
    return pebble_to_return.hash_value

  }

  // Returns a string.
  chain.save = function() {
    return JSON.stringify(chain.state);
  }

  // Loads a string.
  chain.load = function(str_data) {
    chain.state = JSON.parse(str_data);
  }

  return chain;
}

/********* Export functions for testing. ********/


module.exports.naive_chain = naive_chain;
module.exports.pebble_chain = pebble_chain;


/********* End of Original File ********/

