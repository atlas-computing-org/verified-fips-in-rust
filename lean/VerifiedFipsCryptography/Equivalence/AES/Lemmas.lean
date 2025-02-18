import VerifiedFipsCryptography.Specs.AES.AES

namespace AES

@[simp]
lemma rotWord_size (word_size : word.size = 4) : (rotWord word).size = 4 := by
  simp [rotWord, word_size]

@[simp]
lemma subWord_size (word_size : word.size = 4) : (subWord word).size = 4 := by
  simp [subWord, word_size]

end AES
