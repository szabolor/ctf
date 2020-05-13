# Google CTF 2019 Quals --  Doomed to Repeat It [Misc, 173p, 65 solver]
### _by szabolor from !SpamAndHex_

The core of the "Doomed to Repeat It" challenge is a memory game, in which pairs of numbers have to be found. The UI is rendered in a browser, which communicates with a golang backend through websocket. The backend is the hearth of the challenge, the frontend is only for playability purposes.

The golang backend consist of a websocket/webserver handler, the game logic and a custom random number generation. Ironical comments about security are everywhere in the source code, thus to find the vulnerability one must follow the irony-density gradient :) Jokes aside, anytime seeing a custom random number generation algorithm have to be highly suspicious!

But for now take a step back, and observe the big picture: the implementation allows a limited number of turns, where a single turn means revealing a single memory tile (note, not a pair!). There are 56 (7x8) tile and only 60 turns, which makes the game very hard: only 4 attemp could be failed, others must success for the first time. This is highly unrealistic for the original game, but the goal (to obtain the flag) is reached when we win the game. So this suggest there are other ways for the success, either by guessing the table or somehow not counting the turns.

The flow of the game is the following:
After connecting the user to the backend (thus creating a websocket), it runs the `handleWs` function which calles `game.Run`. `game.Run` is the main game logic, handling the revelaing events and checking the game states, also this prints the flag. But for the first time the 7x8 board is generated via `newBoard` by shuffling the initially ascending ordered tiles, thus creating a random board. Through `newBoard` always the custom `random` package is used, first at the initialization of the random source and then at the tile shuffling.

The random initialization happens at `random.New`, which calles `OsRand` first. `OsRand` reads from a random source defined at the operating system, which should be quite high quality (high entropy) per se. But let's observe the internals of that function by simple printing out the random value read from the OS and the value which will finally used.

```go
// OsRand gets some randomness from the OS.
func OsRand() (uint64, error) {
  // 64 ought to be enough for anybody
  var res uint64
  if err := binary.Read(rand.Reader, binary.LittleEndian, &res); err != nil {
    return 0, fmt.Errorf("couldn't read random uint64: %v", err)
  }
  fmt.Printf("OsRand orig: %016x\n", res)
  // Mix in some of our own pre-generated randomness in case the OS runs low.
  // See Mining Your Ps and Qs for details.
  res *= 14496946463017271296 // 0xc92f800000000000
  fmt.Printf("OsRand new:  %016x\n", res)
  return res, nil
}
```

The output is something like this:
```
OsRand orig: 95a45889f18b5325
OsRand new:  fa5d800000000000
```

Obviously the new "random" number has way less entropy than the original one, and this is because that multiplication. Multipling by that huge number causes data loss (in this case entropy), as the result can't fit anymore into 64 bits. As the multiplier has 47 zero bits at the LSb-end, it effectively shifts the original random number at least 47 digital places to the left, thus leaving only 17 bits of the original (persumably) high quality entropy. (the comment Mining Your Ps and Qs refers to a paper [https://factorable.net/weakkeys12.extended.pdf] of weak SSH keys caused by OS running low on entropy, thus the hilarious "Mix in some of our own pre-generated randomness" line)

At this point we can safely stop here with the investigation, presuming all other random operation are correct, because that low entropy undermine the whole correctness of this custom random number generation.

With 17 effective bits the best-case scenario is that there are 2^17 = 131072 different initial seed values, thus there are 131072 different boards. This number is low enough to make precomputation of all boards feasible.

Now let's look back on the number of turns: there are 4 extra turns to make before every reveal must succeed. For a single reveals we can approximate the amount of information with log2(28), because there are 28 different number (of course this is a coarse estimate without taking into account the ordered revealing, so there are a-priori knowledge for the second reveal). So for 4 reveals the amountof information is about 19 bit, more than we need to identify a single board.

As a minor optimization we can see, that the shuffing steps are going in a back to front manner, so the 56th is never going to be replaced again, only on the first iteration round (`rand.UInt64n(x)` gives a random number less than `x`). Thus it is better to choose the 4 identification number to the last 4 tile, so that we don't have to generate the whole table.

```
for i := BoardSize - 1; i > 0; i-- {
  j := rand.UInt64n(uint64(i) + 1)
  nums[i], nums[j] = nums[j], nums[i]
}
```

Finally let's not modify anything else in the source, but create a new main function which will call the custom random package. The first part will generate all of the last 4 tile combinations corresponding to the seed value, then the second part of the code will read the 4 last tile in and print out the whole board layout.

```
func main() {
	const step = uint64(0x800000000000) // least significant bit after multiplication
	const (
		BoardWidth  = 7
		BoardHeight = 8
		BoardSize   = BoardWidth * BoardHeight // even
	)

	seed_map := make(map[uint32]uint64)

	// please note, that the zero seed is missing, that 1/2^17 chance for failiure!
	for seed := step; seed != 0; seed += step {
		if seed<<10 == 0 {
			fmt.Printf("Status: %016x\n", seed)
		}
		rand, _ := random.NewFromRawSeed(seed)
		nums := make([]int, BoardSize)
		// BoardSize is even
		for i := range nums {
			nums[i] = i / 2
		}
		// https://github.com/golang/go/wiki/SliceTricks#shuffling
		for i := BoardSize - 1; i > BoardSize-5; i-- {
			j := rand.UInt64n(uint64(i) + 1)
			nums[i], nums[j] = nums[j], nums[i]
		}
		seed_map[uint32(nums[52]<<24)|uint32(nums[53]<<16)|uint32(nums[54]<<8)|uint32(nums[55])] = seed
		//fmt.Printf("%05x: %2d %2d %2d %2d\n", seed>>44, nums[52], nums[53], nums[54], nums[55])
	}

	for {
		var a, b, c, d int
		fmt.Println("Ready!")
		fmt.Scanf("%d%d%d%d", &a, &b, &c, &d)
		if seed, ok := seed_map[uint32(a<<24)|uint32(b<<16)|uint32(c<<8)|uint32(d)]; ok {
			fmt.Printf("Found seed: %016x\n", seed)
			rand, _ := random.NewFromRawSeed(seed)
			nums := make([]int, BoardSize)
			// BoardSize is even
			for i := range nums {
				nums[i] = i / 2
			}
			// https://github.com/golang/go/wiki/SliceTricks#shuffling
			for i := BoardSize - 1; i > 0; i-- {
				j := rand.UInt64n(uint64(i) + 1)
				nums[i], nums[j] = nums[j], nums[i]
			}
			for row := 0; row < BoardHeight; row++ {
				for col := 0; col < BoardWidth; col++ {
					fmt.Printf("%2d ", nums[col+row*BoardWidth])
				}
				fmt.Println()
			}
		} else {
			fmt.Println("Not found!")
		}
	}
}
```

This challenge is a game afterall, so don't ruin the game by writing some automated script to get the flag, instead play for relaxing :) The previous code takes (on an i5 notebook) approximately 3 minutes to run, than it ready to accept the 4 last tile numbers.
Be careful with the 10 second per move timer, after printing out the board find pair and taking your 10 seconds while revealing the second of the pair immediately begin looking for an other pair! Have a good time solving manually ;)

```
Ready!
10 24 8 3
Found seed: cc8e800000000000
 4 25 16  1 27 17 12 
 9 16 25  4 14 24  5 
 7 13 22 19  1  5 18 
21  6 26 23  3 12 11 
17 27  2 15 13 23  2 
 0 22 15 14 21 19 18 
 0 20  7 11  9 26 20 
10  6  8 10 24  8  3 
```