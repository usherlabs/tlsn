use std::{
    fmt::Debug,
    sync::{Arc, OnceLock},
};

use hmac_sha256_circuits::{build_session_keys, build_verify_data};
use mpz_circuits::Circuit;
use mpz_common::cpu::CpuBackend;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array, View,
    },
    prelude::*,
    Call, Vm as VmTrait,
};
use tracing::instrument;

use crate::{Prf, PrfConfig, PrfError, PrfOutput, Role, SessionKeys, CF_LABEL, SF_LABEL};

pub(crate) struct Circuits {
    session_keys: Arc<Circuit>,
    client_vd: Arc<Circuit>,
    server_vd: Arc<Circuit>,
}

impl Circuits {
    pub(crate) async fn get() -> &'static Self {
        static CIRCUITS: OnceLock<Circuits> = OnceLock::new();
        if let Some(circuits) = CIRCUITS.get() {
            return circuits;
        }

        let (session_keys, client_vd, server_vd) = futures::join!(
            CpuBackend::blocking(build_session_keys),
            CpuBackend::blocking(|| build_verify_data(CF_LABEL)),
            CpuBackend::blocking(|| build_verify_data(SF_LABEL)),
        );

        _ = CIRCUITS.set(Circuits {
            session_keys,
            client_vd,
            server_vd,
        });

        CIRCUITS.get().unwrap()
    }
}

#[derive(Debug)]
pub(crate) enum State {
    Initialized,
    SessionKeys {
        client_random: Array<U8, 32>,
        server_random: Array<U8, 32>,
        cf_hash: Array<U8, 32>,
        sf_hash: Array<U8, 32>,
    },
    ClientFinished {
        cf_hash: Array<U8, 32>,
        sf_hash: Array<U8, 32>,
    },
    ServerFinished {
        sf_hash: Array<U8, 32>,
    },
    Complete,
    Error,
}

impl State {
    fn take(&mut self) -> State {
        std::mem::replace(self, State::Error)
    }
}

/// MPC PRF for computing TLS HMAC-SHA256 PRF.
pub struct MpcPrf {
    config: PrfConfig,
    state: State,
}

impl Debug for MpcPrf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcPrf")
            .field("config", &self.config)
            .field("state", &self.state)
            .finish()
    }
}

impl MpcPrf {
    /// Creates a new instance of the PRF.
    pub fn new(config: PrfConfig) -> MpcPrf {
        MpcPrf {
            config,
            state: State::Initialized,
        }
    }
}

impl<Vm> Prf<Vm> for MpcPrf
where
    Vm: VmTrait<Binary> + View<Binary>,
{
    #[instrument(level = "debug", skip_all, err)]
    fn setup(&mut self, vm: &mut Vm, pms: Array<U8, 32>) -> Result<PrfOutput, PrfError> {
        let State::Initialized = self.state.take() else {
            return Err(PrfError::state("PRF not in initialized state"));
        };

        let circuits = futures::executor::block_on(Circuits::get());

        let client_random = vm.alloc().map_err(PrfError::vm)?;
        let server_random = vm.alloc().map_err(PrfError::vm)?;

        // The client random is kept private so that the handshake transcript
        // hashes do not leak information about the server's identity.
        match self.config.role {
            Role::Leader => vm.mark_private(client_random),
            Role::Follower => vm.mark_blind(client_random),
        }
        .map_err(PrfError::vm)?;

        vm.mark_public(server_random).map_err(PrfError::vm)?;

        #[allow(clippy::type_complexity)]
        let (
            client_write_key,
            server_write_key,
            client_iv,
            server_iv,
            ms_outer_hash_state,
            ms_inner_hash_state,
        ): (
            Array<U8, 16>,
            Array<U8, 16>,
            Array<U8, 4>,
            Array<U8, 4>,
            Array<U32, 8>,
            Array<U32, 8>,
        ) = vm
            .call(
                Call::new(circuits.session_keys.clone())
                    .arg(pms)
                    .arg(client_random)
                    .arg(server_random)
                    .build()
                    .map_err(PrfError::vm)?,
            )
            .map_err(PrfError::vm)?;

        let keys = SessionKeys {
            client_write_key,
            server_write_key,
            client_iv,
            server_iv,
        };

        let cf_hash = vm.alloc().map_err(PrfError::vm)?;
        vm.mark_public(cf_hash).map_err(PrfError::vm)?;

        let cf_vd = vm
            .call(
                Call::new(circuits.client_vd.clone())
                    .arg(ms_outer_hash_state)
                    .arg(ms_inner_hash_state)
                    .arg(cf_hash)
                    .build()
                    .map_err(PrfError::vm)?,
            )
            .map_err(PrfError::vm)?;

        let sf_hash = vm.alloc().map_err(PrfError::vm)?;
        vm.mark_public(sf_hash).map_err(PrfError::vm)?;

        let sf_vd = vm
            .call(
                Call::new(circuits.server_vd.clone())
                    .arg(ms_outer_hash_state)
                    .arg(ms_inner_hash_state)
                    .arg(sf_hash)
                    .build()
                    .map_err(PrfError::vm)?,
            )
            .map_err(PrfError::vm)?;

        self.state = State::SessionKeys {
            client_random,
            server_random,
            cf_hash,
            sf_hash,
        };

        Ok(PrfOutput { keys, cf_vd, sf_vd })
    }

    #[instrument(level = "debug", skip_all, err)]
    fn set_client_random(&mut self, vm: &mut Vm, random: Option<[u8; 32]>) -> Result<(), PrfError> {
        let State::SessionKeys { client_random, .. } = &self.state else {
            return Err(PrfError::state("PRF not set up"));
        };

        if self.config.role == Role::Leader {
            let Some(random) = random else {
                return Err(PrfError::role("leader must provide client random"));
            };

            vm.assign(*client_random, random).map_err(PrfError::vm)?;
        } else if random.is_some() {
            return Err(PrfError::role("only leader can set client random"));
        }

        vm.commit(*client_random).map_err(PrfError::vm)?;

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    fn set_server_random(&mut self, vm: &mut Vm, random: [u8; 32]) -> Result<(), PrfError> {
        let State::SessionKeys {
            server_random,
            cf_hash,
            sf_hash,
            ..
        } = self.state.take()
        else {
            return Err(PrfError::state("PRF not set up"));
        };

        vm.assign(server_random, random).map_err(PrfError::vm)?;
        vm.commit(server_random).map_err(PrfError::vm)?;

        self.state = State::ClientFinished { cf_hash, sf_hash };

        Ok(())
    }

    // #[instrument(level = "debug", skip_all, err)]
    // async fn preprocess(&mut self) -> Result<(), PrfError> {
    //     let State::SessionKeys {
    //         pms,
    //         randoms,
    //         hash_state,
    //         keys,
    //         cf_vd,
    //         sf_vd,
    //     } = self.state.take()
    //     else {
    //         return Err(PrfError::state("PRF not set up"));
    //     };

    //     // Builds all circuits in parallel and preprocesses the session keys
    // circuit.     futures::try_join!(
    //         async {
    //             if SESSION_KEYS_CIRC.get().is_none() {
    //                 _ =
    // SESSION_KEYS_CIRC.set(CpuBackend::blocking(build_session_keys).await);
    //             }

    //             let circ = SESSION_KEYS_CIRC
    //                 .get()
    //                 .expect("session keys circuit should be built");

    //             self.thread_0
    //                 .load(
    //                     circ.clone(),
    //                     &[
    //                         pms.clone(),
    //                         randoms.client_random.clone(),
    //                         randoms.server_random.clone(),
    //                     ],
    //                     &[
    //                         keys.client_write_key.clone(),
    //                         keys.server_write_key.clone(),
    //                         keys.client_iv.clone(),
    //                         keys.server_iv.clone(),
    //                         hash_state.ms_outer_hash_state.clone(),
    //                         hash_state.ms_inner_hash_state.clone(),
    //                     ],
    //                 )
    //                 .await?;

    //             Ok::<_, PrfError>(())
    //         },
    //         async {
    //             if CLIENT_VD_CIRC.get().is_none() {
    //                 _ = CLIENT_VD_CIRC
    //                     .set(CpuBackend::blocking(move ||
    // build_verify_data(CF_LABEL)).await);             }

    //             Ok::<_, PrfError>(())
    //         },
    //         async {
    //             if SERVER_VD_CIRC.get().is_none() {
    //                 _ = SERVER_VD_CIRC
    //                     .set(CpuBackend::blocking(move ||
    // build_verify_data(SF_LABEL)).await);             }

    //             Ok::<_, PrfError>(())
    //         }
    //     )?;

    //     // Finishes preprocessing the verify data circuits.
    //     futures::try_join!(
    //         async {
    //             self.thread_0
    //                 .load(
    //                     CLIENT_VD_CIRC
    //                         .get()
    //                         .expect("client finished circuit should be built")
    //                         .clone(),
    //                     &[
    //                         hash_state.ms_outer_hash_state.clone(),
    //                         hash_state.ms_inner_hash_state.clone(),
    //                         cf_vd.handshake_hash.clone(),
    //                     ],
    //                     &[cf_vd.vd.clone()],
    //                 )
    //                 .await
    //         },
    //         async {
    //             self.thread_1
    //                 .load(
    //                     SERVER_VD_CIRC
    //                         .get()
    //                         .expect("server finished circuit should be built")
    //                         .clone(),
    //                     &[
    //                         hash_state.ms_outer_hash_state.clone(),
    //                         hash_state.ms_inner_hash_state.clone(),
    //                         sf_vd.handshake_hash.clone(),
    //                     ],
    //                     &[sf_vd.vd.clone()],
    //                 )
    //                 .await
    //         }
    //     )?;

    //     self.state = State::SessionKeys {
    //         pms,
    //         randoms,
    //         hash_state,
    //         keys,
    //         cf_vd,
    //         sf_vd,
    //     };

    //     Ok(())
    // }

    #[instrument(level = "debug", skip_all, err)]
    fn set_cf_hash(&mut self, vm: &mut Vm, handshake_hash: [u8; 32]) -> Result<(), PrfError> {
        let State::ClientFinished { cf_hash, sf_hash } = self.state.take() else {
            return Err(PrfError::state("PRF not in client finished state"));
        };

        vm.assign(cf_hash, handshake_hash).map_err(PrfError::vm)?;
        vm.commit(cf_hash).map_err(PrfError::vm)?;

        self.state = State::ServerFinished { sf_hash };

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    fn set_sf_hash(&mut self, vm: &mut Vm, handshake_hash: [u8; 32]) -> Result<(), PrfError> {
        let State::ServerFinished { sf_hash } = self.state.take() else {
            return Err(PrfError::state("PRF not in server finished state"));
        };

        vm.assign(sf_hash, handshake_hash).map_err(PrfError::vm)?;
        vm.commit(sf_hash).map_err(PrfError::vm)?;

        self.state = State::Complete;

        Ok(())
    }
}
