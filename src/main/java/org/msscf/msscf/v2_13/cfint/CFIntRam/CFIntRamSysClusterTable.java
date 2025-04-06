
// Description: Java 11 in-memory RAM DbIO implementation for SysCluster.

/*
 *	org.msscf.msscf.CFInt
 *
 *	Copyright (c) 2020 Mark Stephen Sobkow
 *	
 *	MSS Code Factory CFSec 2.13 Security Essentials
 *	
 *	Copyright 2020-2021 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *
 *	Manufactured by MSS Code Factory 2.12
 */

package org.msscf.msscf.v2_13.cfint.CFIntRam;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import org.msscf.msscf.v2_13.cflib.CFLib.*;
import org.msscf.msscf.v2_13.cfsec.CFSec.*;
import org.msscf.msscf.v2_13.cfint.CFInt.*;
import org.msscf.msscf.v2_13.cfint.CFIntObj.*;
import org.msscf.msscf.v2_13.cfsec.CFSecObj.*;
import org.msscf.msscf.v2_13.cfint.CFIntObj.*;

/*
 *	CFIntRamSysClusterTable in-memory RAM DbIO implementation
 *	for SysCluster.
 */
public class CFIntRamSysClusterTable
	implements ICFIntSysClusterTable
{
	private ICFIntSchema schema;
	private Map< CFSecSysClusterPKey,
				CFSecSysClusterBuff > dictByPKey
		= new HashMap< CFSecSysClusterPKey,
				CFSecSysClusterBuff >();
	private Map< CFSecSysClusterByClusterIdxKey,
				Map< CFSecSysClusterPKey,
					CFSecSysClusterBuff >> dictByClusterIdx
		= new HashMap< CFSecSysClusterByClusterIdxKey,
				Map< CFSecSysClusterPKey,
					CFSecSysClusterBuff >>();

	public CFIntRamSysClusterTable( ICFIntSchema argSchema ) {
		schema = argSchema;
	}

	public void createSysCluster( CFSecAuthorization Authorization,
		CFSecSysClusterBuff Buff )
	{
		final String S_ProcName = "createSysCluster";
		CFSecSysClusterPKey pkey = schema.getFactorySysCluster().newPKey();
		pkey.setRequiredSingletonId( Buff.getRequiredSingletonId() );
		Buff.setRequiredSingletonId( pkey.getRequiredSingletonId() );
		CFSecSysClusterByClusterIdxKey keyClusterIdx = schema.getFactorySysCluster().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableCluster().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"SysClusterCluster",
						"Cluster",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecSysClusterPKey, CFSecSysClusterBuff > subdictClusterIdx;
		if( dictByClusterIdx.containsKey( keyClusterIdx ) ) {
			subdictClusterIdx = dictByClusterIdx.get( keyClusterIdx );
		}
		else {
			subdictClusterIdx = new HashMap< CFSecSysClusterPKey, CFSecSysClusterBuff >();
			dictByClusterIdx.put( keyClusterIdx, subdictClusterIdx );
		}
		subdictClusterIdx.put( pkey, Buff );

	}

	public CFSecSysClusterBuff readDerived( CFSecAuthorization Authorization,
		CFSecSysClusterPKey PKey )
	{
		final String S_ProcName = "CFIntRamSysCluster.readDerived";
		CFSecSysClusterPKey key = schema.getFactorySysCluster().newPKey();
		key.setRequiredSingletonId( PKey.getRequiredSingletonId() );
		CFSecSysClusterBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSysClusterBuff lockDerived( CFSecAuthorization Authorization,
		CFSecSysClusterPKey PKey )
	{
		final String S_ProcName = "CFIntRamSysCluster.readDerived";
		CFSecSysClusterPKey key = schema.getFactorySysCluster().newPKey();
		key.setRequiredSingletonId( PKey.getRequiredSingletonId() );
		CFSecSysClusterBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSysClusterBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFIntRamSysCluster.readAllDerived";
		CFSecSysClusterBuff[] retList = new CFSecSysClusterBuff[ dictByPKey.values().size() ];
		Iterator< CFSecSysClusterBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFSecSysClusterBuff[] readDerivedByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFIntRamSysCluster.readDerivedByClusterIdx";
		CFSecSysClusterByClusterIdxKey key = schema.getFactorySysCluster().newClusterIdxKey();
		key.setRequiredClusterId( ClusterId );

		CFSecSysClusterBuff[] recArray;
		if( dictByClusterIdx.containsKey( key ) ) {
			Map< CFSecSysClusterPKey, CFSecSysClusterBuff > subdictClusterIdx
				= dictByClusterIdx.get( key );
			recArray = new CFSecSysClusterBuff[ subdictClusterIdx.size() ];
			Iterator< CFSecSysClusterBuff > iter = subdictClusterIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSysClusterPKey, CFSecSysClusterBuff > subdictClusterIdx
				= new HashMap< CFSecSysClusterPKey, CFSecSysClusterBuff >();
			dictByClusterIdx.put( key, subdictClusterIdx );
			recArray = new CFSecSysClusterBuff[0];
		}
		return( recArray );
	}

	public CFSecSysClusterBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		int SingletonId )
	{
		final String S_ProcName = "CFIntRamSysCluster.readDerivedByIdIdx() ";
		CFSecSysClusterPKey key = schema.getFactorySysCluster().newPKey();
		key.setRequiredSingletonId( SingletonId );

		CFSecSysClusterBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSysClusterBuff readBuff( CFSecAuthorization Authorization,
		CFSecSysClusterPKey PKey )
	{
		final String S_ProcName = "CFIntRamSysCluster.readBuff";
		CFSecSysClusterBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a014" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSysClusterBuff lockBuff( CFSecAuthorization Authorization,
		CFSecSysClusterPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFSecSysClusterBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a014" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSysClusterBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFIntRamSysCluster.readAllBuff";
		CFSecSysClusterBuff buff;
		ArrayList<CFSecSysClusterBuff> filteredList = new ArrayList<CFSecSysClusterBuff>();
		CFSecSysClusterBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a014" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFSecSysClusterBuff[0] ) );
	}

	public CFSecSysClusterBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		int SingletonId )
	{
		final String S_ProcName = "CFIntRamSysCluster.readBuffByIdIdx() ";
		CFSecSysClusterBuff buff = readDerivedByIdIdx( Authorization,
			SingletonId );
		if( ( buff != null ) && buff.getClassCode().equals( "a014" ) ) {
			return( (CFSecSysClusterBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecSysClusterBuff[] readBuffByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFIntRamSysCluster.readBuffByClusterIdx() ";
		CFSecSysClusterBuff buff;
		ArrayList<CFSecSysClusterBuff> filteredList = new ArrayList<CFSecSysClusterBuff>();
		CFSecSysClusterBuff[] buffList = readDerivedByClusterIdx( Authorization,
			ClusterId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a014" ) ) {
				filteredList.add( (CFSecSysClusterBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSysClusterBuff[0] ) );
	}

	public void updateSysCluster( CFSecAuthorization Authorization,
		CFSecSysClusterBuff Buff )
	{
		CFSecSysClusterPKey pkey = schema.getFactorySysCluster().newPKey();
		pkey.setRequiredSingletonId( Buff.getRequiredSingletonId() );
		CFSecSysClusterBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSysCluster",
				"Existing record not found",
				"SysCluster",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSysCluster",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecSysClusterByClusterIdxKey existingKeyClusterIdx = schema.getFactorySysCluster().newClusterIdxKey();
		existingKeyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecSysClusterByClusterIdxKey newKeyClusterIdx = schema.getFactorySysCluster().newClusterIdxKey();
		newKeyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		// Check unique indexes

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableCluster().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSysCluster",
						"Container",
						"SysClusterCluster",
						"Cluster",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecSysClusterPKey, CFSecSysClusterBuff > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByClusterIdx.get( existingKeyClusterIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByClusterIdx.containsKey( newKeyClusterIdx ) ) {
			subdict = dictByClusterIdx.get( newKeyClusterIdx );
		}
		else {
			subdict = new HashMap< CFSecSysClusterPKey, CFSecSysClusterBuff >();
			dictByClusterIdx.put( newKeyClusterIdx, subdict );
		}
		subdict.put( pkey, Buff );

	}

	public void deleteSysCluster( CFSecAuthorization Authorization,
		CFSecSysClusterBuff Buff )
	{
		final String S_ProcName = "CFIntRamSysClusterTable.deleteSysCluster() ";
		String classCode;
		CFSecSysClusterPKey pkey = schema.getFactorySysCluster().newPKey();
		pkey.setRequiredSingletonId( Buff.getRequiredSingletonId() );
		CFSecSysClusterBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSysCluster",
				pkey );
		}
		CFSecSysClusterByClusterIdxKey keyClusterIdx = schema.getFactorySysCluster().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecSysClusterPKey, CFSecSysClusterBuff > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusterIdx.get( keyClusterIdx );
		subdict.remove( pkey );

	}
	public void deleteSysClusterByIdIdx( CFSecAuthorization Authorization,
		int argSingletonId )
	{
		CFSecSysClusterPKey key = schema.getFactorySysCluster().newPKey();
		key.setRequiredSingletonId( argSingletonId );
		deleteSysClusterByIdIdx( Authorization, key );
	}

	public void deleteSysClusterByIdIdx( CFSecAuthorization Authorization,
		CFSecSysClusterPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecSysClusterBuff cur;
		LinkedList<CFSecSysClusterBuff> matchSet = new LinkedList<CFSecSysClusterBuff>();
		Iterator<CFSecSysClusterBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSysClusterBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSysCluster().readDerivedByIdIdx( Authorization,
				cur.getRequiredSingletonId() );
			deleteSysCluster( Authorization, cur );
		}
	}

	public void deleteSysClusterByClusterIdx( CFSecAuthorization Authorization,
		long argClusterId )
	{
		CFSecSysClusterByClusterIdxKey key = schema.getFactorySysCluster().newClusterIdxKey();
		key.setRequiredClusterId( argClusterId );
		deleteSysClusterByClusterIdx( Authorization, key );
	}

	public void deleteSysClusterByClusterIdx( CFSecAuthorization Authorization,
		CFSecSysClusterByClusterIdxKey argKey )
	{
		CFSecSysClusterBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSysClusterBuff> matchSet = new LinkedList<CFSecSysClusterBuff>();
		Iterator<CFSecSysClusterBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSysClusterBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSysCluster().readDerivedByIdIdx( Authorization,
				cur.getRequiredSingletonId() );
			deleteSysCluster( Authorization, cur );
		}
	}

	public void releasePreparedStatements() {
	}
}
