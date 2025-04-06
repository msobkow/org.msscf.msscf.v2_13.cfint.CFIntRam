
// Description: Java 11 in-memory RAM DbIO implementation for SecGroupForm.

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
 *	CFIntRamSecGroupFormTable in-memory RAM DbIO implementation
 *	for SecGroupForm.
 */
public class CFIntRamSecGroupFormTable
	implements ICFIntSecGroupFormTable
{
	private ICFIntSchema schema;
	private Map< CFSecSecGroupFormPKey,
				CFSecSecGroupFormBuff > dictByPKey
		= new HashMap< CFSecSecGroupFormPKey,
				CFSecSecGroupFormBuff >();
	private Map< CFSecSecGroupFormByClusterIdxKey,
				Map< CFSecSecGroupFormPKey,
					CFSecSecGroupFormBuff >> dictByClusterIdx
		= new HashMap< CFSecSecGroupFormByClusterIdxKey,
				Map< CFSecSecGroupFormPKey,
					CFSecSecGroupFormBuff >>();
	private Map< CFSecSecGroupFormByGroupIdxKey,
				Map< CFSecSecGroupFormPKey,
					CFSecSecGroupFormBuff >> dictByGroupIdx
		= new HashMap< CFSecSecGroupFormByGroupIdxKey,
				Map< CFSecSecGroupFormPKey,
					CFSecSecGroupFormBuff >>();
	private Map< CFSecSecGroupFormByAppIdxKey,
				Map< CFSecSecGroupFormPKey,
					CFSecSecGroupFormBuff >> dictByAppIdx
		= new HashMap< CFSecSecGroupFormByAppIdxKey,
				Map< CFSecSecGroupFormPKey,
					CFSecSecGroupFormBuff >>();
	private Map< CFSecSecGroupFormByFormIdxKey,
				Map< CFSecSecGroupFormPKey,
					CFSecSecGroupFormBuff >> dictByFormIdx
		= new HashMap< CFSecSecGroupFormByFormIdxKey,
				Map< CFSecSecGroupFormPKey,
					CFSecSecGroupFormBuff >>();
	private Map< CFSecSecGroupFormByUFormIdxKey,
			CFSecSecGroupFormBuff > dictByUFormIdx
		= new HashMap< CFSecSecGroupFormByUFormIdxKey,
			CFSecSecGroupFormBuff >();

	public CFIntRamSecGroupFormTable( ICFIntSchema argSchema ) {
		schema = argSchema;
	}

	public void createSecGroupForm( CFSecAuthorization Authorization,
		CFSecSecGroupFormBuff Buff )
	{
		final String S_ProcName = "createSecGroupForm";
		CFSecSecGroupFormPKey pkey = schema.getFactorySecGroupForm().newPKey();
		pkey.setRequiredClusterId( Buff.getRequiredClusterId() );
		pkey.setRequiredSecGroupFormId( ((CFIntRamClusterTable)schema.getTableCluster()).nextSecGroupFormIdGen( Authorization,
			Buff.getRequiredClusterId() ) );
		Buff.setRequiredClusterId( pkey.getRequiredClusterId() );
		Buff.setRequiredSecGroupFormId( pkey.getRequiredSecGroupFormId() );
		CFSecSecGroupFormByClusterIdxKey keyClusterIdx = schema.getFactorySecGroupForm().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecSecGroupFormByGroupIdxKey keyGroupIdx = schema.getFactorySecGroupForm().newGroupIdxKey();
		keyGroupIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyGroupIdx.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );

		CFSecSecGroupFormByAppIdxKey keyAppIdx = schema.getFactorySecGroupForm().newAppIdxKey();
		keyAppIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyAppIdx.setRequiredSecAppId( Buff.getRequiredSecAppId() );

		CFSecSecGroupFormByFormIdxKey keyFormIdx = schema.getFactorySecGroupForm().newFormIdxKey();
		keyFormIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyFormIdx.setRequiredSecFormId( Buff.getRequiredSecFormId() );

		CFSecSecGroupFormByUFormIdxKey keyUFormIdx = schema.getFactorySecGroupForm().newUFormIdxKey();
		keyUFormIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyUFormIdx.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );
		keyUFormIdx.setRequiredSecFormId( Buff.getRequiredSecFormId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUFormIdx.containsKey( keyUFormIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecGroupFormUFormIdx",
				keyUFormIdx );
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
						"Owner",
						"SecGroupFormCluster",
						"Cluster",
						null );
				}
			}
		}

		{
			boolean allNull = true;
			allNull = false;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableSecGroup().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId(),
						Buff.getRequiredSecGroupId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"SecGroupFormGroup",
						"SecGroup",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff > subdictClusterIdx;
		if( dictByClusterIdx.containsKey( keyClusterIdx ) ) {
			subdictClusterIdx = dictByClusterIdx.get( keyClusterIdx );
		}
		else {
			subdictClusterIdx = new HashMap< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff >();
			dictByClusterIdx.put( keyClusterIdx, subdictClusterIdx );
		}
		subdictClusterIdx.put( pkey, Buff );

		Map< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff > subdictGroupIdx;
		if( dictByGroupIdx.containsKey( keyGroupIdx ) ) {
			subdictGroupIdx = dictByGroupIdx.get( keyGroupIdx );
		}
		else {
			subdictGroupIdx = new HashMap< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff >();
			dictByGroupIdx.put( keyGroupIdx, subdictGroupIdx );
		}
		subdictGroupIdx.put( pkey, Buff );

		Map< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff > subdictAppIdx;
		if( dictByAppIdx.containsKey( keyAppIdx ) ) {
			subdictAppIdx = dictByAppIdx.get( keyAppIdx );
		}
		else {
			subdictAppIdx = new HashMap< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff >();
			dictByAppIdx.put( keyAppIdx, subdictAppIdx );
		}
		subdictAppIdx.put( pkey, Buff );

		Map< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff > subdictFormIdx;
		if( dictByFormIdx.containsKey( keyFormIdx ) ) {
			subdictFormIdx = dictByFormIdx.get( keyFormIdx );
		}
		else {
			subdictFormIdx = new HashMap< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff >();
			dictByFormIdx.put( keyFormIdx, subdictFormIdx );
		}
		subdictFormIdx.put( pkey, Buff );

		dictByUFormIdx.put( keyUFormIdx, Buff );

	}

	public CFSecSecGroupFormBuff readDerived( CFSecAuthorization Authorization,
		CFSecSecGroupFormPKey PKey )
	{
		final String S_ProcName = "CFIntRamSecGroupForm.readDerived";
		CFSecSecGroupFormPKey key = schema.getFactorySecGroupForm().newPKey();
		key.setRequiredClusterId( PKey.getRequiredClusterId() );
		key.setRequiredSecGroupFormId( PKey.getRequiredSecGroupFormId() );
		CFSecSecGroupFormBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGroupFormBuff lockDerived( CFSecAuthorization Authorization,
		CFSecSecGroupFormPKey PKey )
	{
		final String S_ProcName = "CFIntRamSecGroupForm.readDerived";
		CFSecSecGroupFormPKey key = schema.getFactorySecGroupForm().newPKey();
		key.setRequiredClusterId( PKey.getRequiredClusterId() );
		key.setRequiredSecGroupFormId( PKey.getRequiredSecGroupFormId() );
		CFSecSecGroupFormBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGroupFormBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFIntRamSecGroupForm.readAllDerived";
		CFSecSecGroupFormBuff[] retList = new CFSecSecGroupFormBuff[ dictByPKey.values().size() ];
		Iterator< CFSecSecGroupFormBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFSecSecGroupFormBuff[] readDerivedByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFIntRamSecGroupForm.readDerivedByClusterIdx";
		CFSecSecGroupFormByClusterIdxKey key = schema.getFactorySecGroupForm().newClusterIdxKey();
		key.setRequiredClusterId( ClusterId );

		CFSecSecGroupFormBuff[] recArray;
		if( dictByClusterIdx.containsKey( key ) ) {
			Map< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff > subdictClusterIdx
				= dictByClusterIdx.get( key );
			recArray = new CFSecSecGroupFormBuff[ subdictClusterIdx.size() ];
			Iterator< CFSecSecGroupFormBuff > iter = subdictClusterIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff > subdictClusterIdx
				= new HashMap< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff >();
			dictByClusterIdx.put( key, subdictClusterIdx );
			recArray = new CFSecSecGroupFormBuff[0];
		}
		return( recArray );
	}

	public CFSecSecGroupFormBuff[] readDerivedByGroupIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecGroupId )
	{
		final String S_ProcName = "CFIntRamSecGroupForm.readDerivedByGroupIdx";
		CFSecSecGroupFormByGroupIdxKey key = schema.getFactorySecGroupForm().newGroupIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredSecGroupId( SecGroupId );

		CFSecSecGroupFormBuff[] recArray;
		if( dictByGroupIdx.containsKey( key ) ) {
			Map< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff > subdictGroupIdx
				= dictByGroupIdx.get( key );
			recArray = new CFSecSecGroupFormBuff[ subdictGroupIdx.size() ];
			Iterator< CFSecSecGroupFormBuff > iter = subdictGroupIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff > subdictGroupIdx
				= new HashMap< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff >();
			dictByGroupIdx.put( key, subdictGroupIdx );
			recArray = new CFSecSecGroupFormBuff[0];
		}
		return( recArray );
	}

	public CFSecSecGroupFormBuff[] readDerivedByAppIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecAppId )
	{
		final String S_ProcName = "CFIntRamSecGroupForm.readDerivedByAppIdx";
		CFSecSecGroupFormByAppIdxKey key = schema.getFactorySecGroupForm().newAppIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredSecAppId( SecAppId );

		CFSecSecGroupFormBuff[] recArray;
		if( dictByAppIdx.containsKey( key ) ) {
			Map< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff > subdictAppIdx
				= dictByAppIdx.get( key );
			recArray = new CFSecSecGroupFormBuff[ subdictAppIdx.size() ];
			Iterator< CFSecSecGroupFormBuff > iter = subdictAppIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff > subdictAppIdx
				= new HashMap< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff >();
			dictByAppIdx.put( key, subdictAppIdx );
			recArray = new CFSecSecGroupFormBuff[0];
		}
		return( recArray );
	}

	public CFSecSecGroupFormBuff[] readDerivedByFormIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecFormId )
	{
		final String S_ProcName = "CFIntRamSecGroupForm.readDerivedByFormIdx";
		CFSecSecGroupFormByFormIdxKey key = schema.getFactorySecGroupForm().newFormIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredSecFormId( SecFormId );

		CFSecSecGroupFormBuff[] recArray;
		if( dictByFormIdx.containsKey( key ) ) {
			Map< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff > subdictFormIdx
				= dictByFormIdx.get( key );
			recArray = new CFSecSecGroupFormBuff[ subdictFormIdx.size() ];
			Iterator< CFSecSecGroupFormBuff > iter = subdictFormIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff > subdictFormIdx
				= new HashMap< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff >();
			dictByFormIdx.put( key, subdictFormIdx );
			recArray = new CFSecSecGroupFormBuff[0];
		}
		return( recArray );
	}

	public CFSecSecGroupFormBuff readDerivedByUFormIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecGroupId,
		int SecFormId )
	{
		final String S_ProcName = "CFIntRamSecGroupForm.readDerivedByUFormIdx";
		CFSecSecGroupFormByUFormIdxKey key = schema.getFactorySecGroupForm().newUFormIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredSecGroupId( SecGroupId );
		key.setRequiredSecFormId( SecFormId );

		CFSecSecGroupFormBuff buff;
		if( dictByUFormIdx.containsKey( key ) ) {
			buff = dictByUFormIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGroupFormBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		long ClusterId,
		long SecGroupFormId )
	{
		final String S_ProcName = "CFIntRamSecGroupForm.readDerivedByIdIdx() ";
		CFSecSecGroupFormPKey key = schema.getFactorySecGroupForm().newPKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredSecGroupFormId( SecGroupFormId );

		CFSecSecGroupFormBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGroupFormBuff readBuff( CFSecAuthorization Authorization,
		CFSecSecGroupFormPKey PKey )
	{
		final String S_ProcName = "CFIntRamSecGroupForm.readBuff";
		CFSecSecGroupFormBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a00d" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGroupFormBuff lockBuff( CFSecAuthorization Authorization,
		CFSecSecGroupFormPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFSecSecGroupFormBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a00d" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGroupFormBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFIntRamSecGroupForm.readAllBuff";
		CFSecSecGroupFormBuff buff;
		ArrayList<CFSecSecGroupFormBuff> filteredList = new ArrayList<CFSecSecGroupFormBuff>();
		CFSecSecGroupFormBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00d" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFSecSecGroupFormBuff[0] ) );
	}

	/**
	 *	Read a page of all the specific SecGroupForm buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecGroupForm instances in the database accessible for the Authorization.
	 */
	public CFSecSecGroupFormBuff[] pageAllBuff( CFSecAuthorization Authorization,
		Long priorClusterId,
		Long priorSecGroupFormId )
	{
		final String S_ProcName = "pageAllBuff";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public CFSecSecGroupFormBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		long ClusterId,
		long SecGroupFormId )
	{
		final String S_ProcName = "CFIntRamSecGroupForm.readBuffByIdIdx() ";
		CFSecSecGroupFormBuff buff = readDerivedByIdIdx( Authorization,
			ClusterId,
			SecGroupFormId );
		if( ( buff != null ) && buff.getClassCode().equals( "a00d" ) ) {
			return( (CFSecSecGroupFormBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecSecGroupFormBuff[] readBuffByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFIntRamSecGroupForm.readBuffByClusterIdx() ";
		CFSecSecGroupFormBuff buff;
		ArrayList<CFSecSecGroupFormBuff> filteredList = new ArrayList<CFSecSecGroupFormBuff>();
		CFSecSecGroupFormBuff[] buffList = readDerivedByClusterIdx( Authorization,
			ClusterId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00d" ) ) {
				filteredList.add( (CFSecSecGroupFormBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecGroupFormBuff[0] ) );
	}

	public CFSecSecGroupFormBuff[] readBuffByGroupIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecGroupId )
	{
		final String S_ProcName = "CFIntRamSecGroupForm.readBuffByGroupIdx() ";
		CFSecSecGroupFormBuff buff;
		ArrayList<CFSecSecGroupFormBuff> filteredList = new ArrayList<CFSecSecGroupFormBuff>();
		CFSecSecGroupFormBuff[] buffList = readDerivedByGroupIdx( Authorization,
			ClusterId,
			SecGroupId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00d" ) ) {
				filteredList.add( (CFSecSecGroupFormBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecGroupFormBuff[0] ) );
	}

	public CFSecSecGroupFormBuff[] readBuffByAppIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecAppId )
	{
		final String S_ProcName = "CFIntRamSecGroupForm.readBuffByAppIdx() ";
		CFSecSecGroupFormBuff buff;
		ArrayList<CFSecSecGroupFormBuff> filteredList = new ArrayList<CFSecSecGroupFormBuff>();
		CFSecSecGroupFormBuff[] buffList = readDerivedByAppIdx( Authorization,
			ClusterId,
			SecAppId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00d" ) ) {
				filteredList.add( (CFSecSecGroupFormBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecGroupFormBuff[0] ) );
	}

	public CFSecSecGroupFormBuff[] readBuffByFormIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecFormId )
	{
		final String S_ProcName = "CFIntRamSecGroupForm.readBuffByFormIdx() ";
		CFSecSecGroupFormBuff buff;
		ArrayList<CFSecSecGroupFormBuff> filteredList = new ArrayList<CFSecSecGroupFormBuff>();
		CFSecSecGroupFormBuff[] buffList = readDerivedByFormIdx( Authorization,
			ClusterId,
			SecFormId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00d" ) ) {
				filteredList.add( (CFSecSecGroupFormBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecGroupFormBuff[0] ) );
	}

	public CFSecSecGroupFormBuff readBuffByUFormIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecGroupId,
		int SecFormId )
	{
		final String S_ProcName = "CFIntRamSecGroupForm.readBuffByUFormIdx() ";
		CFSecSecGroupFormBuff buff = readDerivedByUFormIdx( Authorization,
			ClusterId,
			SecGroupId,
			SecFormId );
		if( ( buff != null ) && buff.getClassCode().equals( "a00d" ) ) {
			return( (CFSecSecGroupFormBuff)buff );
		}
		else {
			return( null );
		}
	}

	/**
	 *	Read a page array of the specific SecGroupForm buffer instances identified by the duplicate key ClusterIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argClusterId	The SecGroupForm key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecSecGroupFormBuff[] pageBuffByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId,
		Long priorClusterId,
		Long priorSecGroupFormId )
	{
		final String S_ProcName = "pageBuffByClusterIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecGroupForm buffer instances identified by the duplicate key GroupIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argClusterId	The SecGroupForm key attribute of the instance generating the id.
	 *
	 *	@param	argSecGroupId	The SecGroupForm key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecSecGroupFormBuff[] pageBuffByGroupIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecGroupId,
		Long priorClusterId,
		Long priorSecGroupFormId )
	{
		final String S_ProcName = "pageBuffByGroupIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecGroupForm buffer instances identified by the duplicate key AppIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argClusterId	The SecGroupForm key attribute of the instance generating the id.
	 *
	 *	@param	argSecAppId	The SecGroupForm key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecSecGroupFormBuff[] pageBuffByAppIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecAppId,
		Long priorClusterId,
		Long priorSecGroupFormId )
	{
		final String S_ProcName = "pageBuffByAppIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecGroupForm buffer instances identified by the duplicate key FormIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argClusterId	The SecGroupForm key attribute of the instance generating the id.
	 *
	 *	@param	argSecFormId	The SecGroupForm key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecSecGroupFormBuff[] pageBuffByFormIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecFormId,
		Long priorClusterId,
		Long priorSecGroupFormId )
	{
		final String S_ProcName = "pageBuffByFormIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public void updateSecGroupForm( CFSecAuthorization Authorization,
		CFSecSecGroupFormBuff Buff )
	{
		CFSecSecGroupFormPKey pkey = schema.getFactorySecGroupForm().newPKey();
		pkey.setRequiredClusterId( Buff.getRequiredClusterId() );
		pkey.setRequiredSecGroupFormId( Buff.getRequiredSecGroupFormId() );
		CFSecSecGroupFormBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecGroupForm",
				"Existing record not found",
				"SecGroupForm",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecGroupForm",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecSecGroupFormByClusterIdxKey existingKeyClusterIdx = schema.getFactorySecGroupForm().newClusterIdxKey();
		existingKeyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecSecGroupFormByClusterIdxKey newKeyClusterIdx = schema.getFactorySecGroupForm().newClusterIdxKey();
		newKeyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecSecGroupFormByGroupIdxKey existingKeyGroupIdx = schema.getFactorySecGroupForm().newGroupIdxKey();
		existingKeyGroupIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyGroupIdx.setRequiredSecGroupId( existing.getRequiredSecGroupId() );

		CFSecSecGroupFormByGroupIdxKey newKeyGroupIdx = schema.getFactorySecGroupForm().newGroupIdxKey();
		newKeyGroupIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyGroupIdx.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );

		CFSecSecGroupFormByAppIdxKey existingKeyAppIdx = schema.getFactorySecGroupForm().newAppIdxKey();
		existingKeyAppIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyAppIdx.setRequiredSecAppId( existing.getRequiredSecAppId() );

		CFSecSecGroupFormByAppIdxKey newKeyAppIdx = schema.getFactorySecGroupForm().newAppIdxKey();
		newKeyAppIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyAppIdx.setRequiredSecAppId( Buff.getRequiredSecAppId() );

		CFSecSecGroupFormByFormIdxKey existingKeyFormIdx = schema.getFactorySecGroupForm().newFormIdxKey();
		existingKeyFormIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyFormIdx.setRequiredSecFormId( existing.getRequiredSecFormId() );

		CFSecSecGroupFormByFormIdxKey newKeyFormIdx = schema.getFactorySecGroupForm().newFormIdxKey();
		newKeyFormIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyFormIdx.setRequiredSecFormId( Buff.getRequiredSecFormId() );

		CFSecSecGroupFormByUFormIdxKey existingKeyUFormIdx = schema.getFactorySecGroupForm().newUFormIdxKey();
		existingKeyUFormIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyUFormIdx.setRequiredSecGroupId( existing.getRequiredSecGroupId() );
		existingKeyUFormIdx.setRequiredSecFormId( existing.getRequiredSecFormId() );

		CFSecSecGroupFormByUFormIdxKey newKeyUFormIdx = schema.getFactorySecGroupForm().newUFormIdxKey();
		newKeyUFormIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyUFormIdx.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );
		newKeyUFormIdx.setRequiredSecFormId( Buff.getRequiredSecFormId() );

		// Check unique indexes

		if( ! existingKeyUFormIdx.equals( newKeyUFormIdx ) ) {
			if( dictByUFormIdx.containsKey( newKeyUFormIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecGroupForm",
					"SecGroupFormUFormIdx",
					newKeyUFormIdx );
			}
		}

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableCluster().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecGroupForm",
						"Owner",
						"SecGroupFormCluster",
						"Cluster",
						null );
				}
			}
		}

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableSecGroup().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId(),
						Buff.getRequiredSecGroupId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecGroupForm",
						"Container",
						"SecGroupFormGroup",
						"SecGroup",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff > subdict;

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
			subdict = new HashMap< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff >();
			dictByClusterIdx.put( newKeyClusterIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByGroupIdx.get( existingKeyGroupIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByGroupIdx.containsKey( newKeyGroupIdx ) ) {
			subdict = dictByGroupIdx.get( newKeyGroupIdx );
		}
		else {
			subdict = new HashMap< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff >();
			dictByGroupIdx.put( newKeyGroupIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByAppIdx.get( existingKeyAppIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByAppIdx.containsKey( newKeyAppIdx ) ) {
			subdict = dictByAppIdx.get( newKeyAppIdx );
		}
		else {
			subdict = new HashMap< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff >();
			dictByAppIdx.put( newKeyAppIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByFormIdx.get( existingKeyFormIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByFormIdx.containsKey( newKeyFormIdx ) ) {
			subdict = dictByFormIdx.get( newKeyFormIdx );
		}
		else {
			subdict = new HashMap< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff >();
			dictByFormIdx.put( newKeyFormIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUFormIdx.remove( existingKeyUFormIdx );
		dictByUFormIdx.put( newKeyUFormIdx, Buff );

	}

	public void deleteSecGroupForm( CFSecAuthorization Authorization,
		CFSecSecGroupFormBuff Buff )
	{
		final String S_ProcName = "CFIntRamSecGroupFormTable.deleteSecGroupForm() ";
		String classCode;
		CFSecSecGroupFormPKey pkey = schema.getFactorySecGroupForm().newPKey();
		pkey.setRequiredClusterId( Buff.getRequiredClusterId() );
		pkey.setRequiredSecGroupFormId( Buff.getRequiredSecGroupFormId() );
		CFSecSecGroupFormBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecGroupForm",
				pkey );
		}
		CFSecSecGroupFormByClusterIdxKey keyClusterIdx = schema.getFactorySecGroupForm().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecSecGroupFormByGroupIdxKey keyGroupIdx = schema.getFactorySecGroupForm().newGroupIdxKey();
		keyGroupIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyGroupIdx.setRequiredSecGroupId( existing.getRequiredSecGroupId() );

		CFSecSecGroupFormByAppIdxKey keyAppIdx = schema.getFactorySecGroupForm().newAppIdxKey();
		keyAppIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyAppIdx.setRequiredSecAppId( existing.getRequiredSecAppId() );

		CFSecSecGroupFormByFormIdxKey keyFormIdx = schema.getFactorySecGroupForm().newFormIdxKey();
		keyFormIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyFormIdx.setRequiredSecFormId( existing.getRequiredSecFormId() );

		CFSecSecGroupFormByUFormIdxKey keyUFormIdx = schema.getFactorySecGroupForm().newUFormIdxKey();
		keyUFormIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyUFormIdx.setRequiredSecGroupId( existing.getRequiredSecGroupId() );
		keyUFormIdx.setRequiredSecFormId( existing.getRequiredSecFormId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecSecGroupFormPKey, CFSecSecGroupFormBuff > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusterIdx.get( keyClusterIdx );
		subdict.remove( pkey );

		subdict = dictByGroupIdx.get( keyGroupIdx );
		subdict.remove( pkey );

		subdict = dictByAppIdx.get( keyAppIdx );
		subdict.remove( pkey );

		subdict = dictByFormIdx.get( keyFormIdx );
		subdict.remove( pkey );

		dictByUFormIdx.remove( keyUFormIdx );

	}
	public void deleteSecGroupFormByIdIdx( CFSecAuthorization Authorization,
		long argClusterId,
		long argSecGroupFormId )
	{
		CFSecSecGroupFormPKey key = schema.getFactorySecGroupForm().newPKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredSecGroupFormId( argSecGroupFormId );
		deleteSecGroupFormByIdIdx( Authorization, key );
	}

	public void deleteSecGroupFormByIdIdx( CFSecAuthorization Authorization,
		CFSecSecGroupFormPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecSecGroupFormBuff cur;
		LinkedList<CFSecSecGroupFormBuff> matchSet = new LinkedList<CFSecSecGroupFormBuff>();
		Iterator<CFSecSecGroupFormBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGroupFormBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGroupForm().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecGroupFormId() );
			deleteSecGroupForm( Authorization, cur );
		}
	}

	public void deleteSecGroupFormByClusterIdx( CFSecAuthorization Authorization,
		long argClusterId )
	{
		CFSecSecGroupFormByClusterIdxKey key = schema.getFactorySecGroupForm().newClusterIdxKey();
		key.setRequiredClusterId( argClusterId );
		deleteSecGroupFormByClusterIdx( Authorization, key );
	}

	public void deleteSecGroupFormByClusterIdx( CFSecAuthorization Authorization,
		CFSecSecGroupFormByClusterIdxKey argKey )
	{
		CFSecSecGroupFormBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecGroupFormBuff> matchSet = new LinkedList<CFSecSecGroupFormBuff>();
		Iterator<CFSecSecGroupFormBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGroupFormBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGroupForm().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecGroupFormId() );
			deleteSecGroupForm( Authorization, cur );
		}
	}

	public void deleteSecGroupFormByGroupIdx( CFSecAuthorization Authorization,
		long argClusterId,
		int argSecGroupId )
	{
		CFSecSecGroupFormByGroupIdxKey key = schema.getFactorySecGroupForm().newGroupIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredSecGroupId( argSecGroupId );
		deleteSecGroupFormByGroupIdx( Authorization, key );
	}

	public void deleteSecGroupFormByGroupIdx( CFSecAuthorization Authorization,
		CFSecSecGroupFormByGroupIdxKey argKey )
	{
		CFSecSecGroupFormBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecGroupFormBuff> matchSet = new LinkedList<CFSecSecGroupFormBuff>();
		Iterator<CFSecSecGroupFormBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGroupFormBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGroupForm().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecGroupFormId() );
			deleteSecGroupForm( Authorization, cur );
		}
	}

	public void deleteSecGroupFormByAppIdx( CFSecAuthorization Authorization,
		long argClusterId,
		int argSecAppId )
	{
		CFSecSecGroupFormByAppIdxKey key = schema.getFactorySecGroupForm().newAppIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredSecAppId( argSecAppId );
		deleteSecGroupFormByAppIdx( Authorization, key );
	}

	public void deleteSecGroupFormByAppIdx( CFSecAuthorization Authorization,
		CFSecSecGroupFormByAppIdxKey argKey )
	{
		CFSecSecGroupFormBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecGroupFormBuff> matchSet = new LinkedList<CFSecSecGroupFormBuff>();
		Iterator<CFSecSecGroupFormBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGroupFormBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGroupForm().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecGroupFormId() );
			deleteSecGroupForm( Authorization, cur );
		}
	}

	public void deleteSecGroupFormByFormIdx( CFSecAuthorization Authorization,
		long argClusterId,
		int argSecFormId )
	{
		CFSecSecGroupFormByFormIdxKey key = schema.getFactorySecGroupForm().newFormIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredSecFormId( argSecFormId );
		deleteSecGroupFormByFormIdx( Authorization, key );
	}

	public void deleteSecGroupFormByFormIdx( CFSecAuthorization Authorization,
		CFSecSecGroupFormByFormIdxKey argKey )
	{
		CFSecSecGroupFormBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecGroupFormBuff> matchSet = new LinkedList<CFSecSecGroupFormBuff>();
		Iterator<CFSecSecGroupFormBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGroupFormBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGroupForm().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecGroupFormId() );
			deleteSecGroupForm( Authorization, cur );
		}
	}

	public void deleteSecGroupFormByUFormIdx( CFSecAuthorization Authorization,
		long argClusterId,
		int argSecGroupId,
		int argSecFormId )
	{
		CFSecSecGroupFormByUFormIdxKey key = schema.getFactorySecGroupForm().newUFormIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredSecGroupId( argSecGroupId );
		key.setRequiredSecFormId( argSecFormId );
		deleteSecGroupFormByUFormIdx( Authorization, key );
	}

	public void deleteSecGroupFormByUFormIdx( CFSecAuthorization Authorization,
		CFSecSecGroupFormByUFormIdxKey argKey )
	{
		CFSecSecGroupFormBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecGroupFormBuff> matchSet = new LinkedList<CFSecSecGroupFormBuff>();
		Iterator<CFSecSecGroupFormBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGroupFormBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGroupForm().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecGroupFormId() );
			deleteSecGroupForm( Authorization, cur );
		}
	}

	public void releasePreparedStatements() {
	}
}
