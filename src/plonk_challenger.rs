use crate::circuit_builder::CircuitBuilder;
use crate::field::extension_field::{Extendable, FieldExtension};
use crate::field::field::Field;
use crate::hash::{permute, SPONGE_RATE, SPONGE_WIDTH};
use crate::proof::{Hash, HashTarget};
use crate::target::Target;

/// Observes prover messages, and generates challenges by hashing the transcript.
#[derive(Clone)]
pub struct Challenger<F: Field> {
    sponge_state: [F; SPONGE_WIDTH],
    input_buffer: Vec<F>,
    output_buffer: Vec<F>,
}

/// Observes prover messages, and generates verifier challenges based on the transcript.
///
/// The implementation is roughly based on a duplex sponge with a Rescue permutation. Note that in
/// each round, our sponge can absorb an arbitrary number of prover messages and generate an
/// arbitrary number of verifier challenges. This might appear to diverge from the duplex sponge
/// design, but it can be viewed as a duplex sponge whose inputs are sometimes zero (when we perform
/// multiple squeezes) and whose outputs are sometimes ignored (when we perform multiple
/// absorptions). Thus the security properties of a duplex sponge still apply to our design.
impl<F: Field> Challenger<F> {
    pub fn new() -> Challenger<F> {
        Challenger {
            sponge_state: [F::ZERO; SPONGE_WIDTH],
            input_buffer: Vec::new(),
            output_buffer: Vec::new(),
        }
    }

    pub fn observe_element(&mut self, element: F) {
        // Any buffered outputs are now invalid, since they wouldn't reflect this input.
        self.output_buffer.clear();

        self.input_buffer.push(element);
    }

    pub fn observe_extension_element<const D: usize>(&mut self, element: &F::Extension)
    where
        F: Extendable<D>,
    {
        for &e in &element.to_basefield_array() {
            self.observe_element(e);
        }
    }

    pub fn observe_elements(&mut self, elements: &[F]) {
        for &element in elements {
            self.observe_element(element);
        }
    }

    pub fn observe_extension_elements<const D: usize>(&mut self, elements: &[F::Extension])
    where
        F: Extendable<D>,
    {
        for element in elements {
            self.observe_extension_element(element);
        }
    }

    pub fn observe_hash(&mut self, hash: &Hash<F>) {
        self.observe_elements(&hash.elements)
    }

    pub fn get_challenge(&mut self) -> F {
        self.absorb_buffered_inputs();

        if self.output_buffer.is_empty() {
            // Evaluate the permutation to produce `r` new outputs.
            self.sponge_state = permute(self.sponge_state);
            self.output_buffer = self.sponge_state[0..SPONGE_RATE].to_vec();
        }

        self.output_buffer
            .pop()
            .expect("Output buffer should be non-empty")
    }

    pub fn get_2_challenges(&mut self) -> (F, F) {
        (self.get_challenge(), self.get_challenge())
    }

    pub fn get_3_challenges(&mut self) -> (F, F, F) {
        (
            self.get_challenge(),
            self.get_challenge(),
            self.get_challenge(),
        )
    }

    pub fn get_n_challenges(&mut self, n: usize) -> Vec<F> {
        (0..n).map(|_| self.get_challenge()).collect()
    }

    pub fn get_hash(&mut self) -> Hash<F> {
        Hash {
            elements: [
                self.get_challenge(),
                self.get_challenge(),
                self.get_challenge(),
                self.get_challenge(),
            ],
        }
    }

    pub fn get_extension_challenge<const D: usize>(&mut self) -> F::Extension
    where
        F: Extendable<D>,
    {
        let mut arr = [F::ZERO; D];
        arr.copy_from_slice(&self.get_n_challenges(D));
        F::Extension::from_basefield_array(arr)
    }

    pub fn get_n_extension_challenges<const D: usize>(&mut self, n: usize) -> Vec<F::Extension>
    where
        F: Extendable<D>,
    {
        (0..n).map(|_| self.get_extension_challenge()).collect()
    }

    /// Absorb any buffered inputs. After calling this, the input buffer will be empty.
    fn absorb_buffered_inputs(&mut self) {
        if self.input_buffer.is_empty() {
            return;
        }

        for input_chunk in self.input_buffer.chunks(SPONGE_RATE) {
            // Overwrite the first r elements with the inputs. This differs from a standard sponge,
            // where we would xor or add in the inputs. This is a well-known variant, though,
            // sometimes called "overwrite mode".
            for (i, &input) in input_chunk.iter().enumerate() {
                self.sponge_state[i] = input;
            }

            // Apply the permutation.
            self.sponge_state = permute(self.sponge_state);
        }

        self.output_buffer = self.sponge_state[0..SPONGE_RATE].to_vec();

        self.input_buffer.clear();
    }
}

impl<F: Field> Default for Challenger<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// A recursive version of `Challenger`.
pub(crate) struct RecursiveChallenger {
    sponge_state: [Target; SPONGE_WIDTH],
    input_buffer: Vec<Target>,
    output_buffer: Vec<Target>,
}

impl RecursiveChallenger {
    pub(crate) fn new<F: Field>(builder: &mut CircuitBuilder<F>) -> Self {
        let zero = builder.zero();
        RecursiveChallenger {
            sponge_state: [zero; SPONGE_WIDTH],
            input_buffer: Vec::new(),
            output_buffer: Vec::new(),
        }
    }

    pub(crate) fn observe_element(&mut self, target: Target) {
        // Any buffered outputs are now invalid, since they wouldn't reflect this input.
        self.output_buffer.clear();

        self.input_buffer.push(target);
    }

    pub(crate) fn observe_elements(&mut self, targets: &[Target]) {
        for &target in targets {
            self.observe_element(target);
        }
    }

    pub fn observe_hash(&mut self, hash: &HashTarget) {
        self.observe_elements(&hash.elements)
    }

    pub(crate) fn get_challenge<F: Field>(&mut self, builder: &mut CircuitBuilder<F>) -> Target {
        self.absorb_buffered_inputs(builder);

        if self.output_buffer.is_empty() {
            // Evaluate the permutation to produce `r` new outputs.
            self.sponge_state = builder.permute(self.sponge_state);
            self.output_buffer = self.sponge_state[0..SPONGE_RATE].to_vec();
        }

        self.output_buffer
            .pop()
            .expect("Output buffer should be non-empty")
    }

    pub(crate) fn get_2_challenges<F: Field>(
        &mut self,
        builder: &mut CircuitBuilder<F>,
    ) -> (Target, Target) {
        (self.get_challenge(builder), self.get_challenge(builder))
    }

    pub(crate) fn get_3_challenges<F: Field>(
        &mut self,
        builder: &mut CircuitBuilder<F>,
    ) -> (Target, Target, Target) {
        (
            self.get_challenge(builder),
            self.get_challenge(builder),
            self.get_challenge(builder),
        )
    }

    pub(crate) fn get_n_challenges<F: Field>(
        &mut self,
        builder: &mut CircuitBuilder<F>,
        n: usize,
    ) -> Vec<Target> {
        (0..n).map(|_| self.get_challenge(builder)).collect()
    }

    /// Absorb any buffered inputs. After calling this, the input buffer will be empty.
    fn absorb_buffered_inputs<F: Field>(&mut self, builder: &mut CircuitBuilder<F>) {
        if self.input_buffer.is_empty() {
            return;
        }

        for input_chunk in self.input_buffer.chunks(SPONGE_RATE) {
            // Overwrite the first r elements with the inputs. This differs from a standard sponge,
            // where we would xor or add in the inputs. This is a well-known variant, though,
            // sometimes called "overwrite mode".
            for (i, &input) in input_chunk.iter().enumerate() {
                self.sponge_state[i] = input;
            }

            // Apply the permutation.
            self.sponge_state = builder.permute(self.sponge_state);
        }

        self.output_buffer = self.sponge_state[0..SPONGE_RATE].to_vec();

        self.input_buffer.clear();
    }
}

#[cfg(test)]
mod tests {
    use crate::circuit_builder::CircuitBuilder;
    use crate::circuit_data::CircuitConfig;
    use crate::field::crandall_field::CrandallField;
    use crate::field::field::Field;
    use crate::generator::generate_partial_witness;
    use crate::plonk_challenger::{Challenger, RecursiveChallenger};
    use crate::target::Target;
    use crate::witness::PartialWitness;

    #[test]
    fn no_duplicate_challenges() {
        type F = CrandallField;
        let mut challenger = Challenger::new();
        let mut challenges = Vec::new();

        for i in 1..10 {
            challenges.extend(challenger.get_n_challenges(i));
            challenger.observe_element(F::rand());
        }

        let dedup_challenges = {
            let mut dedup = challenges.clone();
            dedup.dedup();
            dedup
        };
        assert_eq!(dedup_challenges, challenges);
    }

    /// Tests for consistency between `Challenger` and `RecursiveChallenger`.
    #[test]
    fn test_consistency() {
        type F = CrandallField;

        // These are mostly arbitrary, but we want to test some rounds with enough inputs/outputs to
        // trigger multiple absorptions/squeezes.
        let num_inputs_per_round = vec![2, 5, 3];
        let num_outputs_per_round = vec![1, 2, 4];

        // Generate random input messages.
        let inputs_per_round: Vec<Vec<F>> = num_inputs_per_round
            .iter()
            .map(|&n| F::rand_vec(n))
            .collect();

        let mut challenger = Challenger::new();
        let mut outputs_per_round: Vec<Vec<F>> = Vec::new();
        for (r, inputs) in inputs_per_round.iter().enumerate() {
            challenger.observe_elements(inputs);
            outputs_per_round.push(challenger.get_n_challenges(num_outputs_per_round[r]));
        }

        let config = CircuitConfig {
            num_wires: 12 + 12 + 3 + 101,
            num_routed_wires: 27,
            ..CircuitConfig::default()
        };
        let mut builder = CircuitBuilder::<F>::new(config);
        let mut recursive_challenger = RecursiveChallenger::new(&mut builder);
        let mut recursive_outputs_per_round: Vec<Vec<Target>> = Vec::new();
        for (r, inputs) in inputs_per_round.iter().enumerate() {
            recursive_challenger.observe_elements(&builder.constants(inputs));
            recursive_outputs_per_round.push(
                recursive_challenger.get_n_challenges(&mut builder, num_outputs_per_round[r]),
            );
        }
        let circuit = builder.build();
        let mut witness = PartialWitness::new();
        generate_partial_witness(&mut witness, &circuit.prover_only.generators);
        let recursive_output_values_per_round: Vec<Vec<F>> = recursive_outputs_per_round
            .iter()
            .map(|outputs| witness.get_targets(outputs))
            .collect();

        assert_eq!(outputs_per_round, recursive_output_values_per_round);
    }
}
